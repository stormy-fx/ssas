"""IND MajorLogin request profile adapted from the user-supplied major.py.

The reference contains one device ID and reported IP. Callers supply their
existing account/runtime values instead of reusing those reference identities.
The reference's remaining static fields are retained as supplied and are not
claimed to be a verified or current server protocol.
"""
from datetime import datetime

PROFILE_ID = 'major-py-ind-ob55-2.133.21'
CLIENT_VERSION = '2.133.21'
RELEASE_VERSION = 'OB55'
MAJOR_LOGIN_URL = 'https://loginbp.ppmainecoonghj.com/MajorLogin'


def major_login_headers():
    """Return the reference MajorLogin headers, including its fixed X-GA-SV."""
    return {
        'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
        'Accept': '*/*',
        'Accept-Encoding': 'deflate, gzip',
        'X-GA-SV': '1795314641',
        'Authorization': 'Bearer ',
        'X-GA': 'v1 1',
        'ReleaseVersion': RELEASE_VERSION,
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Unity-Version': '2018.4.12f1',
    }


def _required_text(value, label):
    if value is None or not str(value):
        raise ValueError(label + ' is required')
    return str(value)


def build_fields(open_id, access_token, *, device_id, reported_ip, platform='4',
                 device_profile=None, event_time=None):
    """Build the 60 reference IND scalar fields with account-specific inputs."""
    open_id = _required_text(open_id, 'open ID')
    access_token = _required_text(access_token, 'access token')
    device_id = _required_text(device_id, 'device ID')
    reported_ip = _required_text(reported_ip, 'reported IP')
    platform_text = _required_text(platform, 'platform')
    if not platform_text.isascii() or not platform_text.isdigit():
        raise ValueError('platform must be a nonnegative decimal integer')
    platform_number = int(platform_text)
    if platform_number > 0xffffffff:
        raise ValueError('platform out of range')
    stamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S') if event_time is None else _required_text(event_time, 'event time')
    fields = {
        3: stamp,
        4: 'free fire',
        5: 1,
        7: CLIENT_VERSION,
        8: 'Android OS 15 / API-35 (V2UUIS35.39-21-7-5-1-5/319a58-a9271)',
        9: 'Handheld',
        10: 'airtel',
        11: 'WIFI',
        12: 2400,
        13: 1080,
        14: '400',
        15: 'ARM64 FP ASIMD AES | 4800 | 8',
        16: 7461,
        17: 'Adreno (TM) 710',
        18: 'OpenGL ES 3.2 V@0615.98 (GIT@0c393b63cf, I94e2bd5684, 1746191168) (Date:05/02/25)',
        19: device_id,
        20: reported_ip,
        21: 'en',
        22: open_id,
        23: platform_text,
        24: 'Handheld',
        25: 'motorola moto g96 5G',
        26: 'IND',
        29: access_token,
        30: 1,
        41: 'airtel',
        42: 'WIFI',
        57: '1ac4b80ecf0478a44203bf8fac6120f5',
        60: 111316,
        61: 71883,
        62: 690,
        64: 72011,
        65: 111316,
        66: 72011,
        67: 111316,
        73: 3,
        74: '/data/app/~~xI7rymUmXZFbQjaBVyScAw==/com.dts.freefiremax-lX62T7VsUJ9zo5dV1_axug==/lib/arm64',
        76: 2,
        77: '38f4751a330688ab124c2c804cec90a5|/data/app/~~xI7rymUmXZFbQjaBVyScAw==/com.dts.freefiremax-lX62T7VsUJ9zo5dV1_axug==/base.apk',
        78: 2,
        79: 2,
        81: '64',
        83: '2019118527',
        85: 3,
        86: 'OpenGLES3',
        87: 4095,
        88: platform_number,
        92: 8547,
        93: 'android_max',
        94: 'KqsHTyXD7ugMY7jtv5LX8HvgwlbyeBNDRn1i5gBCkH5Ki7VAs1GQg29x2Voi5Kmo1aQzHcWH/k1nCYf07IMw0ML2tH8+TAnW5tS6cRnMLCAVkS5O',
        95: 111207,
        96: '{"cur_rate":[60,90,120,144],"support_etc2":true}',
        97: 1,
        99: platform_text,
        100: platform_text,
        102: '',
        104: 54845,
        105: 1,
        106: 'https://dl-tata.freefireind.in/live/ABHotUpdates/|https://core-tata.freefireind.in/live/ABHotUpdates/|ac2c27398b1d5d95a4b6b6e04fa94066',
        107: '1.1686d744a88f55b9',
    }
    if device_profile is not None:
        # Preserve the existing caller-supplied device-profile override API.
        width, height = device_profile['resolution']
        fields.update({8: device_profile['os'], 12: int(width), 13: int(height),
                       14: str(device_profile['dpi']), 15: device_profile['cpu'],
                       17: device_profile['gpu'], 18: device_profile['renderer'],
                       25: device_profile['model']})
    return fields


def _varint(value):
    value = int(value)
    if value < 0:
        raise ValueError('negative unsigned protobuf value')
    out = bytearray()
    while value > 127:
        out.append((value & 127) | 128)
        value >>= 7
    out.append(value)
    return bytes(out)


def serialize(fields):
    """Encode reference-order integer and length-delimited scalar fields."""
    output = bytearray()
    for number, value in fields.items():
        number = int(number)
        if number <= 0:
            raise ValueError('invalid protobuf field number')
        if isinstance(value, int):
            output.extend(_varint(number << 3))
            output.extend(_varint(value))
        elif isinstance(value, (str, bytes)):
            data = value.encode('utf-8') if isinstance(value, str) else value
            output.extend(_varint((number << 3) | 2))
            output.extend(_varint(len(data)))
            output.extend(data)
        else:
            raise TypeError('unsupported protobuf field value')
    return bytes(output)
