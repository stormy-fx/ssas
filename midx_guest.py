"""MIDx-source guest-registration adapter for the existing account menu.

The supplied program is untrusted: it is not imported or executed. This small
adapter reproduces its registration/MajorRegister/NewbieChoice flow and, by the
user's explicit choice, its external activator call. The token step uses the
pre-hybrid account generator's existing guest_token routine instead. The
activator gets the freshly-created UID and password in a GET query and can
therefore retain or use those credentials. Never use this with an account whose
credentials you are unwilling to share. New generator calls verify TLS and refuse
redirects; the old token routine is retained with those same safeguards.

No Tor rotation, auto-installer, remote configuration executable, original
banner, saved third-party code or old guest credentials are used. Static source
protocol values may become stale and have not been verified against a live game.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import stat
import string
import tempfile
import time
import uuid

import requests
from shared_accounts import append_account, update_account

SOURCE_SHA256 = '9f71227327b02b2eb071300c6a23aed922a0a804c5fc8ce526c83d02cb40bd44'
REGISTER_URL = 'https://100067.connect.garena.com/api/v2/oauth/guest:register'
GAME_BASE = 'https://loginbp.ppmainecoonghj.com/'
MAJOR_REGISTER_URL = GAME_BASE + 'MajorRegister'
NEWBIE_CHOICE_URL = GAME_BASE + 'ChooseNewbieChoice'
MAJOR_LOGIN_URL = GAME_BASE + 'MajorLogin'
GET_LOGIN_URLS = frozenset((
    'https://client.ind.freefiremobile.com/GetLoginData',
    'https://client.us.freefiremobile.com/GetLoginData',
    'https://clientbp.ggpolarbear.com/GetLoginData',
))
ACTIVATOR_URL = 'https://divan-activator.vercel.app/bind'
SOURCE_APP_ID = 100067
SOURCE_REGISTER_VERSION = '1.132.11'
SOURCE_RELEASE = 'OB55'
SOURCE_LANGUAGE = 'en'
MSDK_USER_AGENT = 'GarenaMSDK/4.0.42(KB2003 ;Android 13;en;HK;app 2.130.1 2019118332;)'
UNITY_USER_AGENT = 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)'
SOURCE_REGIONS = frozenset(('ME', 'IND', 'ID', 'VN', 'TH', 'BD', 'PK', 'TW', 'CIS', 'SAC', 'BR'))
_XOR_KEY = bytes((0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,
                  0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,
                  0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,
                  0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30))
# Statically extracted opaque protocol value from the supplied source, not a
# runtime key or a captured session. Its semantics and server acceptance are
# unverified. No downloaded code is executed to populate it.
_SOURCE_FIELD_22_HEX = (
    '474752450101010062020000a78910bd098e3ff2e4345d59a31db114ea088f37e32e65212ff96621793d9eb78720d0bf2ac9'
    '5176569765247ada5eb01376b3b9931794a4946d76ef8890779f3f2129317e6e1cb2fdcf7b06247cea343b8d4f167eff85a2'
    'e1dfe99b4583a7e1a155dbe7f7f85cff3b223eb77222ec1228f3ee1ef6ce7f8ca24b00a554e497328812f8df74c82d519ae3'
    'e3ceab436eb145e8a517089a7cef6a4efb22214b2a4b19989b74807584afe5e52825e7ac60e19a596a9bf02d961de6a0ed25'
    '15ec6023fdb7684d9464b97b21c527ce61b6bee4ef30d20a1fa33a996952d44d44e44f2f86c768aaf2a7808ad60f91048dca'
    '0207961ba7c2555c48341b30190debc775edb2cee244cf51fca3760ce4388be2db45e80b813b5beb9c784007b7762d7a1e42'
    '8affc8a3a4cd76cbaef648a274297fde33233dccd3f272cb77f39a1affe0365a24954111f768f720e77535af024bea2b2726'
    'c3bac992374755c3deacf09235e6865d456e651680d115a751a797225eaacdf9a513cf104526e1a32e5296e111a33ae581a6'
    '3850837921df8489adfd41ea895b7cf3f5b2e45d538a6e4f032f590ccbb7daf5fa9c50adadee07996614c3f957bda349e6c4'
    '84fdf55970d1943ad7955a76671298b6d98b636b69ebde6bc94dbd93ac3393a6ae230130445b2d744189167854a5617be239'
    '3e7d8fbb5719a1b47541ba466167e3e05a6c244f1301ee2035acf94dffc8adbde747d5cd85e35ead3acc372a59c4220e54bf'
    '63f9d80485f3de2518495c1d0f78c911d2da595911fd2a1989cf17cf3ded5f6c92dea64d675c555c11df92d6c517ca5d0d61'
    'a8962f43f76ec7e87596c8325ebf9ab0f8e6d2eca33c511ceac6980906ebd68c478665591dcecf788ec6ef34cfbe3fcc279c'
    '6147c5bf91cd43cdc9704236'
)
SOURCE_FIELD_22 = bytes.fromhex(_SOURCE_FIELD_22_HEX)
_ALLOWED = frozenset({('POST', REGISTER_URL),
                      ('POST', MAJOR_REGISTER_URL), ('POST', NEWBIE_CHOICE_URL),
                      ('POST', MAJOR_LOGIN_URL), ('GET', ACTIVATOR_URL)}) | frozenset(
                          ('POST', url) for url in GET_LOGIN_URLS)


class GuestStageError(RuntimeError):
    """A redacted error: never include a request URL, response body or secret."""
    def __init__(self, stage, detail):
        self.stage, self.detail = stage, detail
        super().__init__(f'{stage}: {detail}')


def _request(session, method, url, stage, timeout, **kwargs):
    if (method, url) not in _ALLOWED:
        raise GuestStageError(stage, 'destination not allowed')
    try:
        response = session.request(method, url, timeout=timeout, verify=True,
                                   allow_redirects=False, **kwargs)
    except requests.exceptions.Timeout:
        raise GuestStageError(stage, 'timeout; outcome may be unknown') from None
    except requests.exceptions.RequestException:
        raise GuestStageError(stage, 'network or TLS error') from None
    except Exception:
        raise GuestStageError(stage, 'request failed') from None
    status = getattr(response, 'status_code', None)
    if type(status) is not int or status != 200:
        detail = f'HTTP {status}' if type(status) is int and 100 <= status <= 599 else 'invalid HTTP response'
        raise GuestStageError(stage, detail)
    return response


def _json(response, stage):
    try:
        value = response.json()
    except Exception:
        raise GuestStageError(stage, 'invalid JSON response') from None
    if not isinstance(value, dict):
        raise GuestStageError(stage, 'invalid JSON response')
    return value


def _credential(value, name, max_length=32768):
    if not isinstance(value, str) or not 0 < len(value) <= max_length:
        raise GuestStageError(name, 'missing or invalid response field')
    if any(ord(c) < 32 or ord(c) == 127 for c in value) or '|' in value:
        raise GuestStageError(name, 'missing or invalid response field')
    return value


def _uid(value, stage):
    if type(value) not in (str, int):
        raise GuestStageError(stage, 'missing or invalid UID')
    value = str(value)
    if not value.isascii() or not value.isdigit() or len(value) > 24 or int(value) <= 0:
        raise GuestStageError(stage, 'missing or invalid UID')
    return value


def new_password():
    # No password prefix is asked for because the existing UI does not have one.
    # Keep passwords unpredictable instead of reusing an encoded fixed suffix.
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(64))


def new_name(prefix):
    prefix = str(prefix or 'vai')[:7]
    digits = f'{secrets.randbelow(99999) + 1:05d}'
    return prefix + digits.translate(str.maketrans('0123456789', '⁰¹²³⁴⁵⁶⁷⁸⁹'))


def register_guest(session, password, secret):
    payload = {'app_id': SOURCE_APP_ID, 'client_type': 2, 'password': password, 'source': 2}
    body = json.dumps(payload, separators=(',', ':'))
    signature = hmac.new(secret.encode('utf-8'), body.encode('utf-8'), hashlib.sha256).hexdigest()
    headers = {'User-Agent': MSDK_USER_AGENT, 'Accept': 'application/json',
               'Content-Type': 'application/json; charset=utf-8', 'Connection': 'Keep-Alive',
               'Accept-Encoding': 'gzip', 'Authorization': f'Signature {signature}'}
    result = _json(_request(session, 'POST', REGISTER_URL, 'Register', 15,
                            data=body, headers=headers), 'Register')
    if type(result.get('code')) is not int or result.get('code') != 0 or not isinstance(result.get('data'), dict):
        raise GuestStageError('Register', 'registration was not confirmed')
    return _uid(result['data'].get('uid'), 'Register')


def request_token(engine, tag, uid, password):
    """Use the earlier account generator's token routine for this new guest."""
    device_id = '02-' + str(uuid.uuid4())
    try:
        result = engine.guest_token(tag, uid, device_id, password)
    except Exception:
        # The legacy function can embed response data in exception text.
        raise GuestStageError('Token', 'previous generator token grant failed') from None
    if not isinstance(result, dict):
        raise GuestStageError('Token', 'missing or invalid response field')
    access = _credential(result.get('access_token'), 'Token')
    open_id = _credential(result.get('open_id'), 'Token', max_length=1024)
    try:
        platform = int(result.get('platform', result.get('main_active_platform', 4)) or 4)
        if not 0 <= platform <= 255:
            raise ValueError('platform out of range')
    except (TypeError, ValueError, OverflowError):
        raise GuestStageError('Token', 'invalid platform') from None
    return access, open_id, platform


def _varint(value):
    if type(value) is not int or not 0 <= value <= 0xffffffffffffffff:
        raise ValueError('invalid unsigned integer')
    out = bytearray()
    while value >= 128:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def _field_int(number, value):
    return _varint(number << 3) + _varint(value)


def _field_bytes(number, value):
    if isinstance(value, str):
        value = value.encode('utf-8')
    if not isinstance(value, bytes):
        raise ValueError('invalid length-delimited field')
    return _varint((number << 3) | 2) + _varint(len(value)) + value


def _xor_open_id(open_id):
    raw = open_id.encode('utf-8')
    return bytes(value ^ _XOR_KEY[i % len(_XOR_KEY)] for i, value in enumerate(raw))


def major_register_plain(name, token, open_id, registration_version=SOURCE_REGISTER_VERSION):
    fields = ((1, name), (2, token), (3, open_id), (5, 102000007), (6, 4),
              (7, 1), (13, 1), (14, _xor_open_id(open_id)), (15, SOURCE_LANGUAGE),
              (16, 2), (20, registration_version), (21, 1), (22, SOURCE_FIELD_22))
    return b''.join(_field_int(number, value) if isinstance(value, int)
                    else _field_bytes(number, value) for number, value in fields)


def newbie_choice_plain(account_id):
    return _field_int(1, int(account_id)) + _field_int(2, 1) + _field_int(3, 3)


def _read_varint(data, offset):
    result = 0
    for i in range(10):
        if offset >= len(data):
            raise ValueError('truncated varint')
        byte = data[offset]; offset += 1
        if i == 9 and byte > 1:
            raise ValueError('varint overflow')
        result |= (byte & 127) << (7 * i)
        if byte < 128:
            return result, offset
    raise ValueError('overlong varint')


def _major_account_id(data):
    if not isinstance(data, bytes) or len(data) > 1_000_000:
        raise GuestStageError('MajorRegister', 'invalid response')
    pos, found = 0, None
    try:
        while pos < len(data):
            tag, pos = _read_varint(data, pos)
            number, wire = tag >> 3, tag & 7
            if number == 0:
                raise ValueError('invalid field')
            if wire == 0:
                value, pos = _read_varint(data, pos)
            elif wire in (1, 5):
                size = 8 if wire == 1 else 4
                if pos + size > len(data): raise ValueError('truncated fixed field')
                value = data[pos:pos + size]; pos += size
            elif wire == 2:
                size, pos = _read_varint(data, pos)
                if size > len(data) - pos: raise ValueError('truncated field')
                value = data[pos:pos + size]; pos += size
            else:
                raise ValueError('unsupported wire type')
            if number == 3:
                if found is not None: raise ValueError('duplicate account ID')
                if isinstance(value, bytes): value = value.decode('ascii')
                found = _uid(value, 'MajorRegister')
    except (ValueError, UnicodeDecodeError):
        raise GuestStageError('MajorRegister', 'invalid protobuf response') from None
    if found is None:
        raise GuestStageError('MajorRegister', 'account ID missing')
    return found


def _release(cfg):
    value = cfg.get('latest_release_version') or SOURCE_RELEASE
    value = str(value)
    if not value or len(value) > 24 or not all(c.isalnum() or c in '._-' for c in value):
        return SOURCE_RELEASE
    return value


def _version(cfg):
    # The original optional updater is not executed. Only an explicit
    # registration_version from existing configuration can replace the source
    # fallback; remote_version in this project is a separate login setting.
    value = str(cfg.get('registration_version') or SOURCE_REGISTER_VERSION)
    parts = value.split('.')
    if len(parts) != 3 or any(not p.isascii() or not p.isdigit() or len(p) > 4 for p in parts):
        return SOURCE_REGISTER_VERSION
    return value


def _game_headers(release):
    return {'Host': 'loginbp.ppmainecoonghj.com', 'User-Agent': UNITY_USER_AGENT,
            'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip',
            'X-GA-SV': str(int(time.time())), 'Authorization': 'Bearer', 'X-GA': 'v1 1',
            'ReleaseVersion': release, 'Content-Type': 'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.12f1'}


def major_register(session, engine, name, token, open_id, cfg):
    plain = major_register_plain(name, token, open_id, _version(cfg))
    response = _request(session, 'POST', MAJOR_REGISTER_URL, 'MajorRegister', 30,
                        data=engine.enc_aes(plain), headers=_game_headers(_release(cfg)))
    return _major_account_id(response.content)


def newbie_choice(session, engine, account_id, cfg):
    _request(session, 'POST', NEWBIE_CHOICE_URL, 'NewbieChoice', 30,
             data=engine.enc_aes(newbie_choice_plain(account_id)), headers=_game_headers(_release(cfg)))


def _parse_game_message(body, constructor, valid, stage):
    # Mirror the existing parser's optional framing offsets, but do not trust
    # an arbitrary size, and never log or return the raw response.
    if not isinstance(body, bytes) or len(body) > 1_000_000:
        raise GuestStageError(stage, 'invalid protobuf response')
    offsets = [0] + ([64] if len(body) > 64 else [])
    offsets += [i for i in range(1, min(128, len(body))) if i != 64]
    for offset in offsets:
        try:
            message = constructor()
            message.ParseFromString(body[offset:])
            if valid(message):
                return message
        except Exception:
            pass
    raise GuestStageError(stage, 'invalid protobuf response')


def verified_major_login(session, engine, open_id, token, platform, cfg, region):
    """The baseline generator's optional login, with fixed TLS destinations."""
    selected = str(cfg.get('region') or region).upper()
    body = engine.build_major_login_pb2(open_id, token, platform, cfg['remote_version'],
                                        selected, cfg.get('country_code', 'IN'),
                                        cfg.get('lang', 'en'))
    if selected == 'IND':
        url = engine.major_login_profile.MAJOR_LOGIN_URL
        headers = engine.major_login_profile.major_login_headers()
        timeout = 30
    else:
        url = cfg['server_url'].rstrip('/') + '/MajorLogin'
        headers = _game_headers(cfg['latest_release_version'])
        headers.pop('Host')
        timeout = 20
    response = _request(session, 'POST', url, 'Login', timeout, data=body, headers=headers)
    parsed = _parse_game_message(response.content, engine.MajorLoginResponse,
                                 lambda m: bool(m.token and m.account_id), 'Login')
    return {'account_id': parsed.account_id, 'jwt': parsed.token,
            'game_url': getattr(parsed, 'server_url', '') or cfg['server_url'],
            # Preserve whether the server actually provided a region rather
            # than inferring it from the requested configuration.
            'reported_region': getattr(parsed, 'lock_region', '')}


def verified_get_login_data(session, engine, open_id, token, platform, cfg, jwt):
    body = engine.build_get_login_data_pb2(open_id, token, platform, cfg['remote_version'],
                                            jwt, cfg['client_url'], cfg.get('region', 'IND'),
                                            cfg.get('country_code', 'IN'), cfg.get('lang', 'en'))
    headers = _game_headers(cfg['latest_release_version'])
    headers.pop('Host')
    headers['Authorization'] = f'Bearer {jwt}'
    url = cfg['client_url'].rstrip('/') + '/GetLoginData'
    response = _request(session, 'POST', url, 'LoginData', 20, data=body, headers=headers)
    _parse_game_message(response.content, engine.PorTs_pb2.GetLoginData,
                        lambda m: bool(m.AccountUID or m.Online_IP_Port), 'LoginData')


def activate(session, uid, password, region):
    # The supplied source uses a GET query, so this service receives both
    # credentials. No game cookies are shared with the separate session.
    # RU is labelled CIS by that source; other unsupported choices are passed
    # through unchanged, without claiming that the service supports them.
    api_region = 'CIS' if region == 'RU' else region
    last = None
    for attempt in range(2):
        try:
            response = _request(session, 'GET', ACTIVATOR_URL, 'Activator', 25,
                                params={'uid': uid, 'password': password, 'region': api_region},
                                headers={'Accept': 'application/json'})
            data = _json(response, 'Activator')
            if data.get('success') is True:
                # As in the source, only presence is checked; no JWT signature
                # or region binding is independently verified.
                return _credential(data.get('jwt'), 'Activator', max_length=16384)
            if data.get('error') in ('auth_failed', 'login_failed', 'region_bind_rejected'):
                raise GuestStageError('Activator', 'activation rejected')
            raise GuestStageError('Activator', 'activation not confirmed')
        except GuestStageError as exc:
            last = exc
            if exc.detail == 'activation rejected' or attempt == 1:
                break
            time.sleep(1.0)
    raise last


def _open_private_append(path):
    path = Path(path)
    if path.is_symlink():
        raise OSError('account file must not be a symlink')
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW
    if hasattr(os, 'O_NONBLOCK'):
        flags |= os.O_NONBLOCK
    fd = os.open(path, flags, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError('account file must be a regular file')
        if hasattr(os, 'fchmod'):
            os.fchmod(fd, 0o600)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _preflight_store():
    # Check append and atomic-update directory permissions *before* registering
    # an account. Disk-full/interrupt races can still occur afterward.
    fd = _open_private_append('accs.txt')
    os.close(fd)
    fd, name = tempfile.mkstemp(prefix='.accs-check-', dir='.')
    os.close(fd)
    os.unlink(name)


def _save_new(uid, password, region):
    path = Path('accs.txt')
    if path.is_symlink():
        raise OSError('account file must not be a symlink')
    append_account({'uid': uid, 'pass': password, 'name': '', 'region': region, 'platform': 4})


def _save_recovery(uid, password, region):
    # A separate compatible record prevents loss if the main store fails after
    # registration. No network stage continues when this fallback is needed.
    fd = _open_private_append('accs_recovery.txt')
    with os.fdopen(fd, 'a', encoding='utf-8') as f:
        f.write('|'.join((uid, password, '', region, '', '', '', '', '', '4')) + '\n')
        f.flush()
        os.fsync(f.fileno())


def _update(uid, values):
    update_account(uid, values)


def _reported_region(engine, login, requested):
    observed = login.get('reported_region')
    if isinstance(observed, str):
        observed = observed.upper().strip()
        if observed in engine.REGION_LIST:
            return observed, 'login response'
    # The existing parser does not verify JWT signatures. A JWT claim is
    # informative only, not independent proof of a region lock.
    claims = engine.decode_jwt_payload(login.get('jwt', ''))
    observed = claims.get('lock_region') if isinstance(claims, dict) else None
    if isinstance(observed, str):
        observed = observed.upper().strip()
        if observed in engine.REGION_LIST:
            return observed, 'unverified token claim'
    return requested, ''


def create_one_account(engine, index, total, cfg, custom_name=None, *, session_factory=None):
    """Register a new guest and persist its credentials before further stages.

    Never forwards an existing stored account to the activator and never
    automatically repeats an ambiguous registration. Tests pass fake sessions.
    """
    tag = engine._tag(index, total)
    region = str(cfg.get('region') or cfg.get('country_code') or 'IND').upper().strip()
    if region not in engine.REGION_LIST:
        print(f'  X [{tag}] FAILED: invalid region', flush=True)
        return None
    source_region = 'CIS' if region == 'RU' else region
    if source_region not in SOURCE_REGIONS:
        print(f'  Warning: {region} is not listed in the supplied activator; binding may fail.', flush=True)
    elif region == 'BR':
        print('  Warning: the supplied program skipped its activator in BR ghost mode; BR support is unverified.', flush=True)
    factory = session_factory or requests.Session
    game_session = activator_session = None
    uid = None
    saved = False
    try:
        try:
            _preflight_store()
        except Exception:
            print(f'  X [{tag}] FAILED: account store is not writable; no guest registered.', flush=True)
            return None
        game_session = factory()
        game_session.trust_env = False
        activator_session = factory()
        activator_session.trust_env = False
        password = new_password()
        print(f'  [{tag}] register...', end='', flush=True)
        uid = register_guest(game_session, password, engine.SECRET)
        try:
            _save_new(uid, password, region)
        except Exception:
            try:
                _save_recovery(uid, password, region)
                print('  CRITICAL: accs.txt write failed; guest credentials saved to private accs_recovery.txt.', flush=True)
            except Exception:
                # Only as a last resort, reveal the newly issued credentials to
                # their owner once so that they are not irretrievably lost.
                print('\n  CRITICAL: all storage failed. Copy this sensitive recovery line to a private accs.txt:', flush=True)
                print('  ' + '|'.join((uid, password, '', region, '', '', '', '', '', '4')), flush=True)
            return None
        saved = True
        print(f' uid={uid}', end='', flush=True)

        print('  token...', end='', flush=True)
        access_token, open_id, platform = request_token(engine, tag, uid, password)
        _update(uid, {'open_id': open_id, 'access_token': access_token, 'platform': platform})
        print(' ok', end='', flush=True)

        name = new_name(custom_name)
        print(f'  nick... {name}', end='', flush=True)
        print('  majreg...', end='', flush=True)
        account_id = major_register(game_session, engine, name, access_token, open_id, cfg)
        _update(uid, {'name': name, 'ingame_id': account_id})
        print(' ok', end='', flush=True)
        try:
            newbie_choice(game_session, engine, account_id, cfg)
        except GuestStageError as exc:
            print(f'  Warning: newbie choice not confirmed ({exc.detail}).', end='', flush=True)

        # Explicitly selected by the user; the external service gets UID/password.
        # Its messages are quiet, but an error is not treated as successful
        # activation: activation_reported remains False in the return value.
        activated_jwt = ''
        try:
            activated_jwt = activate(activator_session, uid, password, region)
            _update(uid, {'jwt': activated_jwt})
        except GuestStageError:
            pass

        print('  login...', end='', flush=True)
        stored_region, evidence = region, ''
        observed, observed_evidence = region, ''
        login_succeeded = False
        try:
            login = verified_major_login(game_session, engine, open_id, access_token, platform, cfg, region)
            if _uid(login['account_id'], 'Login') != account_id:
                raise GuestStageError('Login', 'account ID mismatch')
            observed, observed_evidence = _reported_region(engine, login, region)
            cfg_use = cfg
            if observed != region:
                cfg_use = engine.build_region_cfg(observed)
                login = verified_major_login(game_session, engine, open_id, access_token, platform, cfg_use, observed)
                if _uid(login['account_id'], 'Login') != account_id:
                    raise GuestStageError('Login', 'account ID mismatch')
                second_region, second_evidence = _reported_region(engine, login, observed)
                if second_evidence and second_region != observed:
                    raise GuestStageError('Login', 'inconsistent reported region')
            jwt = _credential(login['jwt'], 'Login', max_length=16384)
            _update(uid, {'ingame_id': account_id, 'jwt': jwt, 'region': observed,
                          'game_url': login.get('game_url') or cfg_use['server_url']})
            stored_region, evidence = observed, observed_evidence
            login_succeeded = True
            print(' ok', end='', flush=True)
            print('  data...', end='', flush=True)
            try:
                verified_get_login_data(game_session, engine, open_id, access_token, platform, cfg_use, jwt)
                print(' done', end='', flush=True)
            except GuestStageError:
                print(' not confirmed', end='', flush=True)
        except GuestStageError as exc:
            print(f' not confirmed ({exc.detail})', end='', flush=True)
        except Exception:
            print(' not confirmed', end='', flush=True)
        if observed_evidence and observed != region:
            # A different region affects the stored record; show the difference
            # without claiming that activation or region binding succeeded.
            print(f'  Region: requested {region}; {observed_evidence} reported {observed}.', end='', flush=True)
        print('', flush=True)
        return {'uid': uid, 'pass': password, 'name': name, 'ingame_id': account_id,
                'region': stored_region, 'region_report_source': evidence,
                'activation_reported': bool(activated_jwt), 'login_succeeded': login_succeeded}
    except GuestStageError as exc:
        suffix = '; guest credentials saved, registration may be incomplete' if saved else '; creation may be unknown' if exc.stage == 'Register' else ''
        print(f'  X [{tag}] FAILED: {exc}{suffix}', flush=True)
        return None
    except Exception as exc:
        # Never stringify exceptions: they can contain credential-bearing URLs.
        suffix = '; guest credentials saved, registration may be incomplete' if saved else ''
        print(f'  X [{tag}] FAILED: {type(exc).__name__}{suffix}', flush=True)
        return None
    finally:
        for session in (game_session, activator_session):
            if session is not None:
                try:
                    session.close()
                except Exception:
                    pass
