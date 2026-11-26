"""Validation for locally cached login sessions; no network or secret logging.

JWT payloads are read only to reject obvious expiry or inconsistent account
metadata. Their signature is not verified here and passing these checks does
not establish that a server will still accept the cached session.
"""
import base64
import binascii
import hmac
import json
import math

JWT_EXPIRY_MARGIN_SECONDS = 60.0
MAX_JWT_BYTES = 65536


def _number(value):
    return type(value) is int or (type(value) is float and math.isfinite(value))


def _positive_id(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.isascii() and value.isdigit() and len(value) <= 20:
        result = int(value)
    else:
        return None
    return result if 0 < result < (1 << 64) else None


def _key16(value):
    if isinstance(value, (bytes, bytearray)):
        return len(value) == 16
    if isinstance(value, str) and len(value) == 32:
        try:
            return len(bytes.fromhex(value)) == 16
        except ValueError:
            return False
    return False


def _jwt_claims(token):
    if not isinstance(token, str) or not token or len(token) > MAX_JWT_BYTES:
        return None
    parts = token.split('.')
    if len(parts) != 3 or not all(parts):
        return None
    try:
        encoded = parts[1].encode('ascii')
        raw = base64.b64decode(encoded + b'=' * (-len(encoded) % 4),
                               altchars=b'-_', validate=True)
        claims = json.loads(raw)
    except (ValueError, TypeError, UnicodeError, binascii.Error, RecursionError):
        return None
    return claims if isinstance(claims, dict) else None


def valid_session(entry, now, ttl):
    """Check age, usable bridge fields and JWT expiry; never mutate the entry."""
    if (not isinstance(entry, dict) or not _number(now) or not 0 <= now <= 1e12
            or not _number(ttl) or ttl <= 0):
        return False
    saved = entry.get('cached_at')
    if not _number(saved) or saved < 0 or saved > now + 60.0 or now - saved > ttl:
        return False
    account = _positive_id(entry.get('account_id'))
    if account is None or not isinstance(entry.get('login_payload_data'), (bytes, bytearray)):
        return False
    if not entry['login_payload_data']:
        return False
    if not _key16(entry.get('aes_ak')) or not _key16(entry.get('iv_i')):
        return False
    if not all(isinstance(entry.get(field), str) and entry[field].strip()
               for field in ('functional_addrs', 'server_url', 'region', 'client_version', 'release_version')):
        return False
    server_time = entry.get('server_time')
    if isinstance(server_time, bool) or not isinstance(server_time, (str, int)):
        return False
    try:
        server_time = int(server_time)
    except ValueError:
        return False
    if not 0 <= server_time <= 0xffffffff:
        return False
    claims = _jwt_claims(entry.get('token'))
    if claims is None:
        return False
    exp = claims.get('exp')
    if not _number(exp) or exp <= now + JWT_EXPIRY_MARGIN_SECONDS:
        return False
    nbf = claims.get('nbf')
    if nbf is not None and (not _number(nbf) or nbf > now):
        return False
    claim_id = claims.get('account_id')
    if claim_id is not None and _positive_id(claim_id) != account:
        return False
    lock_region = claims.get('lock_region')
    if lock_region is not None and not isinstance(lock_region, str):
        return False
    if lock_region and lock_region.upper() != entry['region'].upper():
        return False
    return True


def _same_secret(a, b):
    if not isinstance(a, str) or not isinstance(b, str) or not a or not b:
        return False
    try:
        return hmac.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
    except UnicodeError:
        return False


def matches_login(entry, *, region, client_version, ind_profile, ind_release,
                  uid=None, password=None, access_token=None):
    """Reject cross-account/region/profile reuse even if a cache key collides."""
    if not isinstance(entry, dict) or not isinstance(region, str):
        return False
    requested = region.upper()
    saved_region = entry.get('region')
    if not isinstance(saved_region, str) or saved_region.upper() != requested:
        return False
    if entry.get('client_version') != client_version:
        return False
    marker = entry.get('major_login_profile')
    if requested == 'IND':
        if marker is None:
            # A pre-marker IND session may be tried, but its login provenance
            # is unknown: matching stored version/release is not proof of the
            # newer MajorLogin profile. Never add a marker to an old entry.
            if entry.get('release_version') != ind_release:
                return False
        elif marker != ind_profile:
            return False
        # Current-profile entries retain the actual version-config release
        # for GetLoginData, which may differ from the fixed MajorLogin header.
    elif marker not in (None, 'legacy'):
        return False
    if uid is not None:
        return (entry.get('auth_type') == 'guest' and
                str(entry.get('auth_uid', '')) == str(uid) and
                _same_secret(entry.get('auth_password'), password))
    if access_token is not None:
        return entry.get('auth_type') == 'token' and _same_secret(entry.get('auth_token'), access_token)
    return False
