"""Strict Google DNS-over-HTTPS for this application's Python network paths.

This is a DNS resolver, not a proxy or a VPN. Packets to resolved destinations
or literal IP addresses still go directly to those destinations. The resolver
uses Google's public numeric bootstrap addresses with certificate verification;
it never retries a failed hostname lookup with the device's DNS.
"""
import http.client
import ipaddress
import json
import os
import socket
import ssl
import sys
import threading
import time
from collections import OrderedDict
from urllib.parse import urlencode

RESOLVER_HOST = 'dns.google.com'
RESOLVER_PATH = '/resolve'
# Google's documented Public DNS addresses also serve DNS-over-HTTPS. Numeric
# addresses avoid the chicken-and-egg problem of resolving the resolver's name.
BOOTSTRAP_IPS = ('8.8.8.8', '8.8.4.4',
                 '2001:4860:4860::8888', '2001:4860:4860::8844')
SOCKET_TIMEOUT = 2.0
QUERY_BUDGET = 6.0
MAX_BODY = 65536
CACHE_LIMIT = 256
MAX_TTL = 300
_NEGATIVE_TTL = 10
_TYPE_CODES = {'A': 1, 'AAAA': 28, 'PTR': 12}

_cache = OrderedDict()
_inflight = {}
_cache_lock = threading.Lock()
_install_lock = threading.RLock()
_installed = False

# These are reset to the currently installed functions immediately before our
# hooks are installed. In particular, test harnesses can block the real socket
# operations before installing this resolver.
_native_getaddrinfo = socket.getaddrinfo
_native_getnameinfo = socket.getnameinfo
_native_connect = socket.socket.connect
_native_connect_ex = socket.socket.connect_ex
_native_sendto = socket.socket.sendto


class _DoHError(Exception):
    """An unusable DNS-over-HTTPS transport or response."""


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect directly to a Google IP but validate TLS for dns.google.com."""

    def __init__(self, bootstrap_ip, timeout):
        context = ssl.create_default_context()
        super().__init__(RESOLVER_HOST, port=443, timeout=timeout, context=context)
        self._bootstrap_ip = bootstrap_ip

    def connect(self):
        ip = ipaddress.ip_address(self._bootstrap_ip)
        family = socket.AF_INET if ip.version == 4 else socket.AF_INET6
        raw = socket.socket(family, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.timeout)
            raw.connect((str(ip), 443))
            # Keep the requested hostname for both SNI and certificate checks.
            self.sock = self._context.wrap_socket(raw, server_hostname=RESOLVER_HOST)
        except BaseException:
            raw.close()
            raise


def _text(host):
    if isinstance(host, bytes):
        try:
            return host.decode('ascii')
        except UnicodeDecodeError:
            raise socket.gaierror(socket.EAI_NONAME, 'Invalid hostname') from None
    if not isinstance(host, str):
        raise TypeError('hostname must be a string, bytes or None')
    return host


def _literal(host):
    try:
        return ipaddress.ip_address(_text(host))
    except (ValueError, TypeError, socket.gaierror):
        return None


def _hostname(host):
    host = _text(host)
    if not host or host != host.strip() or any(ord(c) < 33 or ord(c) == 127 for c in host):
        raise socket.gaierror(socket.EAI_NONAME, 'Invalid hostname')
    if host.endswith('.'):
        host = host[:-1]
    try:
        ascii_name = host.encode('idna').decode('ascii').lower()
    except (UnicodeError, ValueError):
        raise socket.gaierror(socket.EAI_NONAME, 'Invalid hostname') from None
    labels = ascii_name.split('.')
    allowed = frozenset('abcdefghijklmnopqrstuvwxyz0123456789-_')
    if (not ascii_name or len(ascii_name) > 253 or any(
            not label or len(label) > 63 or any(c not in allowed for c in label)
            for label in labels)):
        raise socket.gaierror(socket.EAI_NONAME, 'Invalid hostname')
    return ascii_name


def _fetch_json(name, kind, bootstrap_ip, timeout):
    """Fetch only DNS question data; no cookies, app headers or proxy settings."""
    conn = _PinnedHTTPSConnection(bootstrap_ip, timeout)
    try:
        path = RESOLVER_PATH + '?' + urlencode({'name': name, 'type': kind})
        conn.request('GET', path, headers={'Accept': 'application/dns-json',
                                          'Connection': 'close'})
        response = conn.getresponse()
        if response.status != 200:
            raise _DoHError('Google DoH HTTP error')
        body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise _DoHError('Oversized Google DoH response')
        result = json.loads(body.decode('utf-8'))
        if not isinstance(result, dict):
            raise _DoHError('Invalid Google DoH response')
        return result
    finally:
        conn.close()


def _parse_reply(reply, name, kind):
    """Validate the question and collect matching answer records and TTL."""
    status = reply.get('Status')
    question = reply.get('Question')
    if (type(status) is not int or reply.get('TC') not in (False, 0, None)
            or not isinstance(question, list) or len(question) != 1
            or not isinstance(question[0], dict)
            or question[0].get('type') != _TYPE_CODES[kind]
            or str(question[0].get('name', '')).lower().rstrip('.') != name):
        raise _DoHError('Invalid or truncated Google DoH response')
    if status == 3:  # NXDOMAIN; do not ask another resolver.
        return (), _NEGATIVE_TTL
    if status != 0:
        raise _DoHError('Google DoH reported a DNS error')
    answers = reply.get('Answer', [])
    if not isinstance(answers, list):
        raise _DoHError('Invalid Google DoH answers')
    values, ttls = [], []
    for row in answers:
        if not isinstance(row, dict):
            continue
        if row.get('type') in (_TYPE_CODES[kind], 5):  # also honor CNAME TTL
            ttl = row.get('TTL')
            if type(ttl) is int and ttl >= 0:
                ttls.append(ttl)
        if row.get('type') != _TYPE_CODES[kind] or not isinstance(row.get('data'), str):
            continue
        value = row['data']
        try:
            if kind == 'PTR':
                value = _hostname(value)
            else:
                parsed = ipaddress.ip_address(value)
                if parsed.version != (4 if kind == 'A' else 6):
                    continue
                value = str(parsed)
        except (ValueError, TypeError, socket.gaierror):
            continue
        if value not in values:
            values.append(value)
        if len(values) >= 32:
            break
    ttl = min(ttls) if ttls else (_NEGATIVE_TTL if not values else 0)
    return tuple(values), min(MAX_TTL, ttl)


def _uncached_query(name, kind):
    deadline = time.monotonic() + QUERY_BUDGET
    for bootstrap in BOOTSTRAP_IPS:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            reply = _fetch_json(name, kind, bootstrap, min(SOCKET_TIMEOUT, remaining))
            return _parse_reply(reply, name, kind)
        except Exception:
            # Never print exception details; retry only another Google address.
            continue
    raise socket.gaierror(socket.EAI_AGAIN, 'Google DNS unavailable; no system DNS fallback')


def _lookup(name, kind):
    """Per-process TTL cache and single-flight deduplication, safe for threads."""
    key = (name, kind)
    with _cache_lock:
        cached = _cache.get(key)
        now = time.monotonic()
        if cached and cached[0] > now:
            _cache.move_to_end(key)
            return cached[1]
        _cache.pop(key, None)
        state = _inflight.get(key)
        owner = state is None
        if owner:
            state = {'event': threading.Event(), 'result': None, 'error': None}
            _inflight[key] = state
    if not owner:
        if not state['event'].wait(QUERY_BUDGET * 3):
            raise socket.gaierror(socket.EAI_AGAIN, 'Google DNS lookup timed out')
        if state['error'] is not None:
            raise socket.gaierror(*state['error'])
        return state['result']
    try:
        result, ttl = _uncached_query(name, kind)
        state['result'] = result
        if ttl > 0:
            with _cache_lock:
                _cache[key] = (time.monotonic() + ttl, result)
                _cache.move_to_end(key)
                while len(_cache) > CACHE_LIMIT:
                    _cache.popitem(last=False)
        return result
    except BaseException:
        state['error'] = (socket.EAI_AGAIN, 'Google DNS unavailable; no system DNS fallback')
        raise
    finally:
        with _cache_lock:
            _inflight.pop(key, None)
            state['event'].set()


def _numeric_info(address, port, family, socktype, proto, flags):
    """Use the OS only for numeric sockaddr formatting/service lookup, not DNS."""
    return _native_getaddrinfo(address, port, family, socktype, proto,
                               flags | socket.AI_NUMERICHOST)


def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
    """socket.getaddrinfo-compatible forward lookup using Google only."""
    if host is None:
        # getaddrinfo(NULL, ...) computes wildcard/loopback listen addresses.
        return _native_getaddrinfo(None, port, family, type, proto, flags)
    text = _text(host)
    literal = _literal(text)
    if literal is not None:
        return _numeric_info(text, port, family, type, proto, flags)
    if flags & socket.AI_NUMERICHOST:
        raise socket.gaierror(socket.EAI_NONAME, 'Numeric host required')
    name = _hostname(text)
    if family not in (0, socket.AF_UNSPEC, socket.AF_INET, socket.AF_INET6):
        raise socket.gaierror(socket.EAI_FAMILY, 'Unsupported address family')
    if name == 'localhost' or name.endswith('.localhost'):
        addresses = []
        if family in (0, socket.AF_UNSPEC, socket.AF_INET):
            addresses.append(('127.0.0.1', socket.AF_INET))
        if family in (0, socket.AF_UNSPEC, socket.AF_INET6):
            addresses.append(('::1', socket.AF_INET6))
    else:
        addresses, errors = [], []
        kinds = []
        if family in (0, socket.AF_UNSPEC, socket.AF_INET):
            kinds.append(('A', socket.AF_INET))
        if family in (0, socket.AF_UNSPEC, socket.AF_INET6):
            kinds.append(('AAAA', socket.AF_INET6))
        for kind, af in kinds:
            try:
                addresses.extend((value, af) for value in _lookup(name, kind))
            except socket.gaierror as exc:
                errors.append(exc)
        # Honor the usual AF_INET6 + AI_V4MAPPED request without local DNS.
        mapped = getattr(socket, 'AI_V4MAPPED', 0)
        all_flag = getattr(socket, 'AI_ALL', 0)
        if (family == socket.AF_INET6 and flags & mapped
                and (not addresses or (all_flag and flags & all_flag))):
            try:
                addresses.extend(('::ffff:' + value, socket.AF_INET6)
                                 for value in _lookup(name, 'A'))
            except socket.gaierror as exc:
                errors.append(exc)
        if not addresses and errors:
            raise socket.gaierror(socket.EAI_AGAIN, 'Google DNS unavailable; no system DNS fallback')
    result, native_errors = [], []
    for address, af in addresses:
        try:
            rows = _numeric_info(address, port, af, type, proto, flags)
        except socket.gaierror as exc:
            native_errors.append(exc)
            continue
        for row in rows:
            if flags & socket.AI_CANONNAME and not result:
                row = (row[0], row[1], row[2], name, row[4])
            result.append(row)
    if not result:
        if native_errors:
            raise native_errors[-1]
        raise socket.gaierror(socket.EAI_NONAME, 'No address returned by Google DNS')
    return result


def gethostbyname(host):
    return getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM)[0][4][0]


def gethostbyname_ex(host):
    rows = getaddrinfo(host, 0, socket.AF_INET, socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(row[4][0] for row in rows))
    return (_text(host), [], addresses)


def gethostbyaddr(host):
    literal = _literal(host)
    if literal is None:
        literal = ipaddress.ip_address(gethostbyname(host))
    if literal.is_loopback:
        return ('localhost', [], [str(literal)])
    # Strip a possible IPv6 interface scope before building the PTR name.
    literal = ipaddress.ip_address(str(literal).split('%', 1)[0])
    names = _lookup(literal.reverse_pointer, 'PTR')
    if not names:
        raise socket.herror(1, 'No PTR record returned by Google DNS')
    return (names[0], list(names[1:]), [str(literal)])


def getnameinfo(sockaddr, flags):
    # NI_NUMERICHOST controls the result, not necessarily parsing of the input:
    # some platforms still resolve an input hostname in C. Resolve it here first.
    if not isinstance(sockaddr, tuple) or len(sockaddr) not in (2, 4):
        raise TypeError('getnameinfo requires an IPv4 or IPv6 address tuple')
    if _literal(sockaddr[0]) is None:
        family = socket.AF_INET6 if len(sockaddr) == 4 else socket.AF_INET
        kind = socket.SOCK_DGRAM if flags & getattr(socket, 'NI_DGRAM', 0) else socket.SOCK_STREAM
        row = getaddrinfo(sockaddr[0], sockaddr[1], family, kind)[0]
        sockaddr = (row[4][0],) + sockaddr[1:]
    # The native call now sees a numeric host only; service names still use
    # the local services database, not the network DNS resolver.
    req = getattr(socket, 'NI_NAMEREQD', 0)
    numeric_flags = (flags | socket.NI_NUMERICHOST) & ~req
    host, service = _native_getnameinfo(sockaddr, numeric_flags)
    if flags & socket.NI_NUMERICHOST:
        return host, service
    try:
        name = gethostbyaddr(host)[0]
    except (socket.gaierror, socket.herror, ValueError):
        if flags & req:
            raise socket.gaierror(socket.EAI_NONAME, 'Google DNS has no reverse name') from None
        return host, service
    if flags & getattr(socket, 'NI_NOFQDN', 0):
        name = name.split('.', 1)[0]
    return name, service


def _destination(sock, address):
    """Resolve hostname socket destinations before native connect/sendto.

    Raw socket methods can otherwise resolve names in C, bypassing the Python
    getaddrinfo hook. Numeric addresses and non-IP sockets are left unchanged.
    """
    if (sock.family not in (socket.AF_INET, socket.AF_INET6)
            or not isinstance(address, tuple) or len(address) < 2):
        return address
    host = address[0]
    if not isinstance(host, (str, bytes)) or _literal(host) is not None:
        return address
    if not host:
        raise socket.gaierror(socket.EAI_NONAME, 'Missing destination hostname')
    row = getaddrinfo(host, address[1], sock.family, sock.type, sock.proto)[0]
    # Keep a caller's supplied port, flowinfo and scope ID.
    return (row[4][0],) + address[1:]


def _connect(sock, address):
    return _native_connect(sock, _destination(sock, address))


def _connect_ex(sock, address):
    return _native_connect_ex(sock, _destination(sock, address))


def _sendto(sock, data, *args):
    if len(args) in (1, 2):
        args = args[:-1] + (_destination(sock, args[-1]),)
    return _native_sendto(sock, data, *args)


def _threaded_aiohttp_resolver():
    # aiohttp can otherwise select the optional c-ares/aiodns resolver, which
    # bypasses socket.getaddrinfo and would use the device's DNS configuration.
    try:
        import aiohttp.connector
        import aiohttp.resolver
    except ImportError:
        return
    aiohttp.resolver.DefaultResolver = aiohttp.resolver.ThreadedResolver
    aiohttp.connector.DefaultResolver = aiohttp.resolver.ThreadedResolver


def install():
    """Install process-local hooks; safe to call again after installing deps."""
    global _installed, _native_getaddrinfo, _native_getnameinfo
    global _native_connect, _native_connect_ex, _native_sendto
    with _install_lock:
        if not _installed:
            _native_getaddrinfo = socket.getaddrinfo
            _native_getnameinfo = socket.getnameinfo
            _native_connect = socket.socket.connect
            _native_connect_ex = socket.socket.connect_ex
            _native_sendto = socket.socket.sendto
            socket.getaddrinfo = getaddrinfo
            socket.gethostbyname = gethostbyname
            socket.gethostbyname_ex = gethostbyname_ex
            socket.gethostbyaddr = gethostbyaddr
            socket.getnameinfo = getnameinfo
            socket.socket.connect = _connect
            socket.socket.connect_ex = _connect_ex
            socket.socket.sendto = _sendto
            # An HTTP CONNECT proxy may resolve the target remotely, outside
            # this resolver. Disable inherited proxies in this process only.
            for name in ('http_proxy', 'https_proxy', 'all_proxy', 'ftp_proxy',
                         'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'FTP_PROXY',
                         'PIP_PROXY'):
                os.environ.pop(name, None)
            os.environ['NO_PROXY'] = '*'
            os.environ['no_proxy'] = '*'
            _installed = True
        # Call on every install: aiohttp may have been installed since the
        # first call during automatic dependency setup.
        _threaded_aiohttp_resolver()


if __name__ == '__main__':
    install()
    try:
        result = getaddrinfo('example.com', 443, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        print('Google DNS check failed; the app will not fall back to device DNS.', file=sys.stderr)
        raise SystemExit(1)
    print('Google DNS check succeeded for example.com:', result[0][4][0])
