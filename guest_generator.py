# Termux FF Guest Account Generator CLI (Interactive)
# Banner: Guest | Dev: @the_babarrrr
# Usage: python guest.py

import os, sys, time, threading, json, random, requests, re, codecs, base64, hmac, hashlib, string, logging, glob
from datetime import datetime, timezone
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import urllib3
import concurrent.futures
import uuid
import ipaddress
from device_profiles import DEFAULT_REPORTED_IP
import major_login_profile



# ========== LOG ==========
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', stream=sys.stdout)
log = logging.getLogger("ffgen")

# ========== CONFIG ==========
REGION_LANG = {"ME":"ar","IND":"hi","ID":"id","VN":"vi","TH":"th","BD":"bn","PK":"ur","TW":"zh","CIS":"ru","SAC":"es","BR":"pt"}
HEX_KEY = bytes.fromhex("32656534343831396539623435393838343531343130363762323831363231383734643064356437616639643866376530306331653534373135623764316533")
HEX_KEY_STR = HEX_KEY.decode()

OPT = {'timeout': (15, 25), 'retries': 0}
RARITY_SCORE_THRESHOLD = 8
FIXED_WORKERS      = 150
TARGET_ACC_PER_SEC = 100.0
RELEASE_VER        = "OB55"
GAME_VERSION       = "2.132.4"

# ========== IP SPOOFING ==========
def _build_ip_pool():
    pool = set()
    ranges = [
        ("1.",400),("5.",400),("14.",400),("27.",400),("31.",400),("36.",400),("37.",400),("39.",400),
        ("41.",400),("42.",400),("43.",400),("45.",400),("46.",400),("47.",400),("49.",400),("58.",400),
        ("59.",400),("60.",400),("61.",400),("62.",400),("77.",400),("78.",400),("79.",400),("80.",400),
        ("81.",400),("82.",400),("83.",400),("84.",400),("85.",400),("86.",400),("87.",400),("88.",400),
        ("89.",400),("90.",400),("91.",400),("92.",400),("93.",400),("94.",400),("95.",400),("101.",400),
        ("102.",400),("103.",400),("104.",400),("105.",400),("106.",400),("107.",400),("108.",400),("109.",400),
        ("110.",400),("111.",400),("112.",400),("113.",400),("114.",400),("115.",400),("116.",400),("117.",400),
        ("118.",400),("119.",400),("120.",400),("121.",400),("122.",400),("123.",400),("124.",400),("125.",400),
        ("126.",400),("128.",400),("129.",400),("130.",400),("131.",400),("132.",400),("133.",400),("134.",400),
        ("135.",400),("136.",400),("137.",400),("138.",400),("139.",400),("140.",400),("141.",400),("142.",400),
        ("143.",400),("144.",400),("145.",400),("146.",400),("147.",400),("148.",400),("149.",400),("150.",400),
        ("151.",400),("152.",400),("153.",400),("154.",400),("155.",400),("156.",400),("157.",400),("158.",400),
        ("159.",400),("160.",400),("161.",400),("162.",400),("163.",400),("164.",400),("165.",400),("166.",400),
        ("167.",400),("168.",400),("169.",400),("170.",400),("171.",400),("172.",400),("173.",400),("174.",400),
        ("175.",400),("176.",400),("177.",400),("178.",400),("179.",400),("180.",400),("181.",400),("182.",400),
        ("183.",400),("184.",400),("185.",400),("186.",400),("187.",400),("188.",400),("189.",400),("190.",400),
        ("191.",400),("192.",400),("193.",400),("194.",400),("195.",400),("196.",400),("197.",400),("198.",400),
        ("199.",400),("200.",400),("201.",400),("202.",400),("203.",400),("204.",400),("205.",400),("206.",400),
        ("207.",400),("208.",400),("209.",400),("210.",400),("211.",400),("212.",400),("213.",400),("214.",400),
        ("215.",400),("216.",400),("217.",400),("218.",400),("219.",400),("220.",400),("221.",400),("222.",400),
        ("223.",400),
    ]
    private_ranges = [
        ipaddress.ip_network("10.0.0.0/8"), ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"), ipaddress.ip_network("127.0.0.0/8"),
        ipaddress.ip_network("169.254.0.0/16"), ipaddress.ip_network("224.0.0.0/4"),
        ipaddress.ip_network("240.0.0.0/4"),
    ]
    for pfx, cnt in ranges:
        for _ in range(cnt):
            ip_str = f"{pfx}{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                if any(ip_obj in net for net in private_ranges): continue
                pool.add(ip_str)
            except Exception: continue
    pl = list(pool); random.shuffle(pl); return pl

IP_POOL = []

def pick_ip():
    if not IP_POOL: return f"{random.randint(1,223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return IP_POOL[random.randint(0, len(IP_POOL) - 1)]

def ip_headers():
    # Forwarded IP headers do not change the real source IP; avoid spoofing them.
    return {}

# ========== DEVICE POOL ==========
class DevicePool:
    _devices, _index, _lock = [], 0, threading.Lock()
    DEVICE_MODELS = [
        ("Asus ASUS_I005DA", "ARMv7 VFPv3 NEON VMH | 2400 | 2", "Adreno (TM) 640"),
        ("SM-A525F", "ARMv8 VFPv4 NEON VMH | 2200 | 8", "Adreno (TM) 618"),
        ("SM-A325M", "ARMv8 VFPv4 NEON VMH | 2000 | 8", "Mali-G52"),
        ("SM-S918B", "ARMv8 VFPv4 NEON VMH | 3200 | 8", "Adreno (TM) 740"),
        ("Redmi Note 10","ARMv8 VFPv4 NEON VMH | 2200 | 8","Adreno (TM) 619"),
        ("Redmi Note 11","ARMv8 VFPv4 NEON VMH | 2400 | 8","Adreno (TM) 610"),
        ("Poco X3","ARMv8 VFPv4 NEON VMH | 2300 | 8","Adreno (TM) 618"),
        ("Poco M4 Pro","ARMv8 VFPv4 NEON VMH | 2200 | 8","Mali-G57"),
        ("Pixel 6","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G78"),
        ("Pixel 7 Pro","ARMv8 VFPv4 NEON VMH | 2800 | 8","Mali-G710"),
        ("OnePlus 9","ARMv8 VFPv4 NEON VMH | 2800 | 8","Adreno (TM) 660"),
        ("OnePlus 11","ARMv8 VFPv4 NEON VMH | 3200 | 8","Adreno (TM) 740"),
        ("Xiaomi 13 Pro","ARMv8 VFPv4 NEON VMH | 3200 | 8","Adreno (TM) 740"),
        ("Infinix X6819","ARMv8 VFPv4 NEON VMH | 2400 | 8","Mali-G57"),
        ("vivo 1906","ARMv8 VFPv4 NEON VMH | 2000 | 8","Adreno (TM) 610"),
        ("OPPO CPH2211","ARMv8 VFPv4 NEON VMH | 2200 | 8","Adreno (TM) 619"),
        ("realme RMX3363","ARMv8 VFPv4 NEON VMH | 2400 | 8","Adreno (TM) 642"),
        ("TECNO KI5","ARMv8 VFPv4 NEON VMH | 2000 | 8","Mali-G52"),
    ]
    ANDROID_VERSIONS = [
        ("Android OS 9 / API-28 (PI/rel.cjw.20220518.114133)","9","28"),
        ("Android OS 10 / API-29 (QKQ1.200114.002)","10","29"),
        ("Android OS 11 / API-30 (RP1A.201005.001)","11","30"),
        ("Android OS 12 / API-31 (SP1A.210812.016)","12","31"),
        ("Android OS 12L / API-32 (SP2A.220505.002)","12","32"),
        ("Android OS 13 / API-33 (TQ3A.230805.001)","13","33"),
        ("Android OS 14 / API-34 (UP1A.231005.007)","14","34"),
    ]
    NETWORKS  = ["WIFI","4G","5G"]
    OPERATORS = ["ATM Mobils","Telkomsel","Indosat","XL Axiata","Airtel","Jio","Vodafone","Globe","Smart","Viettel","Mobifone","Claro","Vivo"]
    SDK_VER   = ["4.0.38","4.0.39","4.0.40","4.0.41","4.0.42"]

    @classmethod
    def _rh(cls, n): return ''.join(random.choices("0123456789abcdef", k=n))
    @classmethod
    def _uuid(cls): return f"{cls._rh(8)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(4)}-{cls._rh(12)}"
    @classmethod
    def _mac(cls):  return "02:" + ":".join(cls._rh(2) for _ in range(5))

    @classmethod
    def init_pool(cls, count=2500):
        if cls._devices: return
        for _ in range(count):
            model, cpu, gpu = random.choice(cls.DEVICE_MODELS)
            android_full, android_ver, api = random.choice(cls.ANDROID_VERSIONS)
            dev = {
                "model": model, "brand": model.split()[0], "cpu": cpu, "gpu": gpu, "android_full": android_full,
                "android_version": android_ver, "api_level": api, "operator": random.choice(cls.OPERATORS),
                "network": random.choice(cls.NETWORKS), "sdk": random.choice(cls.SDK_VER), "mac": cls._mac(),
                "device_id": cls._rh(32), "android_id": cls._rh(16), "uuid": cls._uuid(), "imei": cls._rh(15),
                "fingerprint": cls._rh(40), "gl_renderer": "OpenGL ES 3.2", "lang_code": random.choice(["en","in","ar","hi","vi","th","pt","ru","es","bn","ur","zh"]),
            }
            dev["_hdr"] = {
                "X-Device-Id": dev["device_id"], "X-Android-Id": dev["android_id"], "X-Device-Model": dev["model"],
                "X-Device-Brand": dev["brand"], "X-OS-Version": dev["android_version"], "X-API-Level": dev["api_level"],
                "X-SDK-Version": dev["sdk"], "X-Network-Type": dev["network"], "X-Operator": dev["operator"],
                "X-IMEI": dev["imei"], "X-Mac": dev["mac"], "X-Client-Uuid": dev["uuid"],
            }
            dev["_gpu_full"] = f"{gpu}|OpenGL ES 3.2"
            cls._devices.append(dev)

    @classmethod
    def get(cls):
        with cls._lock:
            dev = cls._devices[cls._index % len(cls._devices)]
            cls._index += 1
            return dev

    @classmethod
    def headers(cls, device=None):
        return (device or cls.get()).get("_hdr") or {}

DevicePool.init_pool(32)
_thread_local = threading.local()

def get_thread_device():
    if not hasattr(_thread_local, "device"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.device

def get_thread_dev_headers():
    if not hasattr(_thread_local, "dev_headers"):
        _thread_local.device = DevicePool.get()
        _thread_local.dev_headers = _thread_local.device["_hdr"]
    return _thread_local.dev_headers

def reset_thread_session():
    s = getattr(_thread_local, "session", None)
    if s is not None: s.cookies.clear()

def get_thread_session():
    s = getattr(_thread_local, "session", None)
    if s is None:
        s = requests.Session()
        adapter = requests.adapters.HTTPAdapter(pool_connections=8, pool_maxsize=8, max_retries=0, pool_block=False)
        s.mount("https://", adapter)
        s.mount("http://", adapter)
        s.verify = True
        s.headers.update({"Accept": "application/json", "Accept-Encoding": "gzip, deflate", "Connection": "keep-alive"})
        _thread_local.session = s
    return s

def encode_f14(s):
    ks = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
    return bytes(ord(c) ^ ks[i % len(ks)] for i, c in enumerate(s))

FIELD_22 = bytes.fromhex("4747524501010100620200001052aa0d669c6a368f08338060d2ee0690053af84a41edcd3558556ec10f24f46c93ac64ca41a16732c46a2cb071246a79b8929032f9e1b6f4ef331bd53cabf29b09b97349a46e9863c0314e1a0d80819fef8aabf03876b3d037db354a7ccb5c1bce96411fb3753f6f50e44c69c4ed617fa30efb8ffc0517ff2f636739be1f304d999cfd6fd48bf69454199794c3dc88f55a4bdbd66534d5a061359cdfd1fb680cd37918df9fdb3cf7d80067b0a3506c90063cf62b2ccec11e23913a2fd7c4ef091331967bb518a5ad1e551146b90821be800883abadde39d6c80a5d798611466c748f075481806c5842ce45e6bd4e3368ec08fe2ec41ceb880cd86249eb71693f79f0bccf9e590c3fae12519fe08c7a1905d0927690109e0df28574bb14847225db1a59230e6662ed7730e15ff9a6c815cb41b420edeada735a4b03e181037c37c2c850257311df2f07b0a56e759372cbd0268e3f13a292ee4373e38ab5096e0342a5e0d7fec6da2bbc265d74baadd2b24ee4f74862f82c21d6694bac53f8ce80312a30068a6276a641c19b11d0305c6fe2f531ac7de578b29f543697f5c73663e6f23aa15277b6122dcd4d4171e38f9ac0b173f39c58416a16c5c1f4a35acd065ce78f449cf538a249339e763272d458e4ed86c976591a9c066b3a37111e44091eb6b5a795249f3e5145db022a6055f2cc675936391312f688f89627845df222a91156555225be36f9714a0ba50246d0f003bda3c9c1292ab73b4f79635ddd023218eda93a302d79e023404c14396544a930b98ed54771aca7fec10d095587685b473e81a9619764fad9256529dcd6e911f4f4629612287d4ee3ec5389f6ec4ec020b0e2aac017232a9197be9e46239ce690fe5d4872b2e98e651510c971667f3aca8b59f3e9d50e43")

USER_AGENTS_POOL = [
    "GarenaMSDK/4.0.39(SM-A325M;Android 13;en;HK;)", "GarenaMSDK/4.0.38(Redmi Note 10;Android 12;en;ID;)",
    "GarenaMSDK/4.0.40(Poco X3;Android 11;en;SG;)", "GarenaMSDK/4.0.41(SM-S918B;Android 14;en;IN;)",
    "GarenaMSDK/4.0.42(OnePlus 11;Android 13;en;US;)",
]

def random_ua(): return random.choice(USER_AGENTS_POOL)

def _merge_headers(headers, device=None, rotate_ip=False):
    merged = dict(headers or {})
    dev_h = DevicePool.headers(device) if device is not None else get_thread_dev_headers()
    for k, v in dev_h.items(): merged.setdefault(k, v)
    if rotate_ip or "X-Forwarded-For" not in merged: merged.update(ip_headers())
    return merged

def _diagnostic(*args, **kwargs):
    """Routine diagnostic output intentionally hidden."""
    return None


def request_retry(method, url, tag="HTTP", *, exact_headers=False, **kwargs):
    """One verified request; report only the stage, status and exception type."""
    sess = get_thread_session()
    try:
        kwargs.setdefault('timeout', OPT['timeout'])
        kwargs['headers'] = (dict(kwargs.get('headers') or {}) if exact_headers else
                             _merge_headers(kwargs.get('headers'), rotate_ip=False))
        kwargs['verify'] = True
        response = sess.request(method, url, **kwargs)
        if response.status_code != 200:
            _diagnostic(f"  [GUEST] {tag}: HTTP {response.status_code}", flush=True)
        return response
    except requests.exceptions.SSLError:
        _diagnostic(f"  [GUEST] {tag}: TLS certificate verification failed; update Termux certificates.", flush=True)
    except requests.exceptions.Timeout:
        _diagnostic(f"  [GUEST] {tag}: network timeout; outcome of registration may be unknown.", flush=True)
    except requests.exceptions.ConnectionError:
        _diagnostic(f"  [GUEST] {tag}: network connection failed.", flush=True)
    except Exception as exc:
        _diagnostic(f"  [GUEST] {tag}: {type(exc).__name__}.", flush=True)
    return None


def _safe_guest_code(response):
    if response is None: return None
    try:
        value = response.json().get('code')
        return value if type(value) is int and -999999 <= value <= 999999 else None
    except (ValueError, TypeError, AttributeError):
        return None


def _register_guest_with_fallback(url, headers, body):
    """Use original flow first. On explicit HTTP 403, try old DataDome cookie once."""
    active_headers = headers
    resp = request_retry('POST', url, tag='Register', headers=active_headers, data=body)
    if resp is not None and resp.status_code == 403:
        _diagnostic('  [GUEST] Registration was rejected (403); trying the previous DataDome registration flow once.', flush=True)
        try:
            from br_engine import get_datadome
            cookie = get_datadome('guest-fallback')
            active_headers = dict(headers); active_headers['Cookie'] = 'datadome=' + cookie
            resp = request_retry('POST', url, tag='Register fallback', headers=active_headers, data=body)
        except Exception as exc:
            _diagnostic(f'  [GUEST] Registration fallback failed: {type(exc).__name__}.', flush=True)
            return None
    # Explicit rate-limit rejections indicate no successful creation; retry once.
    if resp is not None and (resp.status_code == 429 or _safe_guest_code(resp) in (1005, 1006)):
        _diagnostic('  [GUEST] Registration rate limited; retrying once after 10 seconds.', flush=True)
        time.sleep(10)
        resp = request_retry('POST', url, tag='Register retry', headers=active_headers, data=body)
    return resp


def encode_varint(n):
    if n < 0: return b''
    result = []
    while True:
        byte = n & 0x7F; n >>= 7
        if n: byte |= 0x80
        result.append(byte)
        if not n: break
    return bytes(result)

def create_proto_field(field_num, value):
    if isinstance(value, dict):
        nested = create_proto_field(field_num, value)
        return encode_varint((field_num << 3) | 2) + encode_varint(len(nested)) + nested
    elif isinstance(value, int):
        return encode_varint((field_num << 3) | 0) + encode_varint(value)
    elif isinstance(value, (str, bytes)):
        ev = value.encode() if isinstance(value, str) else value
        return encode_varint((field_num << 3) | 2) + encode_varint(len(ev)) + ev
    return b''

def build_proto(fields):
    return b''.join(create_proto_field(k, v) for k, v in fields.items())

_AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
_AES_IV  = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

def aes_encrypt(hex_data):
    data = bytes.fromhex(hex_data)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(data, AES.block_size))

def encrypt_api(plain_hex):
    plain = bytes.fromhex(plain_hex)
    return AES.new(_AES_KEY, AES.MODE_CBC, _AES_IV).encrypt(pad(plain, AES.block_size)).hex()

def generate_random_name(name_prefix):
    # Superscript numbers mapping
    superscripts = str.maketrans("0123456789", "⁰¹²³⁴⁵⁶⁷⁸⁹")
    rand_num = str(random.randint(1000, 9999))
    return name_prefix + rand_num.translate(superscripts)

def create_account(region, account_name, password_prefix):
    try:
        reset_thread_session()
        rand_part = "".join(random.choices("0123456789ABCDEF", k=16))
        password = f"{password_prefix}_{rand_part}"
        url = "https://100067.connect.garena.com/api/v2/oauth/guest:register"
        payload = {"app_id": 100067, "client_type": 2, "password": password, "source": 2}
        body_json = json.dumps(payload, separators=(",", ":"))
        signature = hmac.new(HEX_KEY, body_json.encode("utf-8"), hashlib.sha256).hexdigest()

        dev = get_thread_device()
        headers = _merge_headers({
            "User-Agent": random_ua(), "Connection": "Keep-Alive", "Accept": "application/json",
            "Accept-Encoding": "gzip", "Authorization": f"Signature {signature}",
            "Content-Type": "application/json; charset=utf-8", "Host": "100067.connect.garena.com",
        }, device=dev)

        resp = _register_guest_with_fallback(url, headers, body_json)
        if resp is not None and resp.status_code == 200:
            res = resp.json()
            if "data" in res and "uid" in res["data"]:
                uid = str(res["data"]["uid"])
                # Save immediately; a later token/login failure must not lose a created guest.
                from shared_accounts import append_account
                append_account({'uid': uid, 'pass': password, 'region': region, 'name': '', 'platform': 4})
                _diagnostic(f"  Guest {uid} saved; game registration and region not yet confirmed.", flush=True)
                return get_token(uid, password, region, account_name, password_prefix)
            code = _safe_guest_code(resp)
            _diagnostic(f"  [GUEST] Register: no UID in response; code={code if code is not None else 'unavailable'}.", flush=True)
        return None
    except Exception as exc:
        _diagnostic(f"  [GUEST] Register/save: {type(exc).__name__}.", flush=True)
        return None

def get_token(uid, password, region, account_name, password_prefix):
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        dev = get_thread_device()
        headers = _merge_headers({"Content-Type": "application/x-www-form-urlencoded", "User-Agent": random_ua()}, device=dev)
        body = {"uid": uid, "password": password, "response_type": "token", "client_type": "2", "client_secret": HEX_KEY_STR, "client_id": "100067"}

        resp = request_retry('POST', url, tag="Token", headers=headers, data=body)
        if resp and resp.status_code == 200 and 'open_id' in resp.json():
            j = resp.json()
            open_id = j['open_id']
            access_token = j["access_token"]

            keystream = [0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30,0x31,0x37,0x30,0x30,0x30,0x30,0x30,0x32,0x30]
            encoded = "".join(chr(ord(open_id[i]) ^ keystream[i % len(keystream)]) for i in range(len(open_id)))
            field = codecs.decode(''.join(c if 32 <= ord(c) <= 126 else f'\\u{ord(c):04x}' for c in encoded), 'unicode_escape').encode('latin1')
            return major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, access_token)
        if resp is not None and resp.status_code == 200:
            _diagnostic('  [GUEST] Token: response missing required fields.', flush=True)
        return None
    except Exception as exc:
        _diagnostic(f"  [GUEST] Token: {type(exc).__name__}.", flush=True)
        return None

def major_register(access_token, open_id, field, uid, password, region, account_name, password_prefix, raw_access_token):
    try:
        url = ("https://loginbp.ppmainecoonghj.com/MajorRegister" if region.upper() not in ["ME","TH"] else "https://loginbp.common.ggbluefox.com/MajorRegister")
        name = generate_random_name(account_name)
        dev = get_thread_device()
        headers = _merge_headers({
            'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
            'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip', 'Authorization': 'Bearer', 'X-GA': 'v1 1',
            'ReleaseVersion': RELEASE_VER, 'Content-Type': 'application/x-www-form-urlencoded', 'X-Unity-Version': '2018.4.12f1',
        }, device=dev)
        lang = REGION_LANG.get(region.upper(), "en")
        reg_msg = {1: name, 2: access_token, 3: open_id, 5: 102000007, 6: 4, 7: 1, 13: 1, 14: encode_f14(open_id), 15: lang, 16: 2, 20: GAME_VERSION, 21: 1, 22: FIELD_22}
        encrypted = aes_encrypt(build_proto(reg_msg).hex())
        register_response = request_retry('POST', url, tag="MajorRegister", headers=headers, data=encrypted)
        if register_response is None:
            _diagnostic('  [GUEST] MajorRegister: no response; checking login anyway.', flush=True)
        login_result = major_login(uid, password, raw_access_token, open_id, region)
        account_id = login_result.get("account_id", "N/A")
        jwt_token  = login_result.get("jwt_token", "")
        if account_id != "N/A":
            bind_status = None
            if jwt_token and region.upper() != "BR":
                bind_status = force_region_bind(region, jwt_token)
                # A 200 response is not enough: ask MajorLogin for a fresh server region.
                refreshed = major_login(uid, password, raw_access_token, open_id, region)
                if refreshed.get('account_id') != 'N/A':
                    login_result = refreshed
                    jwt_token = refreshed.get('jwt_token') or jwt_token
            reported_region = login_result.get('region') or ''
            from shared_accounts import update_account
            stored_region = reported_region or region.upper()
            update_account(uid, {'name': name, 'ingame_id': account_id,
                                 'open_id': open_id, 'access_token': raw_access_token,
                                 'jwt': jwt_token, 'region': stored_region, 'platform': 4})
            if reported_region and reported_region != region.upper():
                print(f"  Warning: requested {region.upper()}, but server reported {reported_region}.", flush=True)
            elif not reported_region:
                print(f"  Warning: {region.upper()} region is unconfirmed; saved as requested.", flush=True)
            return {
                "uid": uid, "game_uid": account_id, "open_id": open_id, "token": raw_access_token, 
                "jwt_token": jwt_token, "password": password, "name": name, "region": stored_region, "region_verified": bool(reported_region),
                "device_model": dev["model"], "device_id": dev["device_id"], "created_at": datetime.now().isoformat()
            }
        _diagnostic('  [GUEST] MajorLogin did not return a usable game account; guest credentials are saved.', flush=True)
        return None
    except Exception as exc:
        _diagnostic(f"  [GUEST] Game registration/save: {type(exc).__name__}; guest credentials may be saved.", flush=True)
        return None

def build_login_payload(access_token, open_id, region):
    lang = REGION_LANG.get(region.upper(), "en")
    dev  = get_thread_device()
    gpu_full, gpu, model = dev["_gpu_full"], dev["gpu"], dev["model"]
    os_str, operator, network = dev["android_full"], dev["operator"], dev["network"]
    device_uuid, cpu = dev["uuid"], dev["cpu"]
    ip_addr = pick_ip()
    open_id_b = open_id.encode() if isinstance(open_id, str) else open_id
    access_token_b = access_token.encode() if isinstance(access_token, str) else access_token

    payload_dict = {
        3:  datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S'), 
        4:  b'free fire', 5: 1, 7: GAME_VERSION, 8: os_str, 9: b'Handheld',
        10: operator, 11: network, 12: 1280, 13: 720, 14: b'240', 15: cpu, 16: random.choice([5951, 6000, 6100, 5500]),
        17: gpu, 18: gpu_full, 19: f'Google|{device_uuid}', 20: ip_addr, 21: lang, 22: open_id_b,
        23: b'4', 24: b'Handheld', 25: model, 26: lang, 29: access_token_b, 30: 1, 41: operator, 42: network,
        57: b'1ac4b80ecf0478a44203bf8fac6120f5', 60: 30000, 61: 30000, 62: 2519, 63: 243,
        64: 32357, 65: 34308, 66: 32357, 67: 34308, 73: 1,
        74: b'/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/lib/arm',
        76: 2, 77: b'428775ab8c8845bd341b5357ec61d15e|/data/app/~~iw-K-GR3srU7dLE-UxJ4bg==/com.dts.freefiremax-kbPhw3SUYautW0I_oayB_A==/base.apk',
        78: 2, 79: 1, 81: b'32', 83: b'2019118525', 85: 3, 86: b'OpenGLES3', 87: 4095, 88: 4,
        92: random.choice([19788, 20000, 21000]), 93: b'android_max',
        94: b'KqsHT2gyPt7vUCc9SCjv2ioi3WEZSEL86ErvXB38suVVK/Z4IVt78ESl/r2S15C1pqu/j6ZmgFL7HbwoFiiVconX08ooKiisQffvEAPCo/C+Lahr',
        96: b'{"cur_rate":null,"support_etc2":true}', 97: 1, 98: 1, 99: b'4', 100: b'4', 102: b'', 104: 77149, 105: 1,
        106: b'https://dl.cdn.freefiremobile.com/live/ABHotUpdates/|https://dl-core.cdn.freefiremobile.com/live/ABHotUpdates/|6b2078db9d22dd98f8e9386a39af8462',
        107: b'c8e41b7a93f02d56e1a94c7b8203f5d1',
    }
    data = build_proto(payload_dict)
    return data


def major_login(uid, password, access_token, open_id, region):
    try:
        dev = get_thread_device()
        reference_profile = region.upper() == "IND"
        if reference_profile:
            fields = major_login_profile.build_fields(
                open_id, access_token, device_id=f"Google|{dev['uuid']}",
                reported_ip=DEFAULT_REPORTED_IP, platform='4')
            data = major_login_profile.serialize(fields)
            url = major_login_profile.MAJOR_LOGIN_URL
            headers = major_login_profile.major_login_headers()
        else:
            data = build_login_payload(access_token, open_id, region)
            url = ("https://loginbp.ppmainecoonghj.com/MajorLogin" if region.upper() not in ["ME", "TH"] else "https://loginbp.common.ggbluefox.com/MajorLogin")
            headers = _merge_headers({
                'User-Agent': 'UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)',
                'Accept': '*/*', 'Accept-Encoding': 'deflate, gzip', 'Authorization': 'Bearer', 'X-GA': 'v1 1', 'X-Ga-Sv': '1789534056',
                'ReleaseVersion': RELEASE_VER, 'Content-Type': 'application/x-www-form-urlencoded', 'X-Unity-Version': '2018.4.12f1',
            }, device=dev)

        enc_hex = encrypt_api(data.hex())
        options = {'timeout': 30, 'exact_headers': True} if reference_profile else {}
        resp = request_retry('POST', url, tag="MajorLogin", headers=headers, data=bytes.fromhex(enc_hex), **options)

        if resp and resp.status_code == 200 and len(resp.text) > 10:
            jwt_start = resp.text.find("eyJ")
            if jwt_start != -1:
                jwt_token = resp.text[jwt_start:]
                second_dot = jwt_token.find(".", jwt_token.find(".") + 1)
                if second_dot != -1:
                    jwt_token = jwt_token[:second_dot + 44]
                    try:
                        parts = jwt_token.split('.')
                        if len(parts) >= 2:
                            pp = parts[1]
                            padding = 4 - len(pp) % 4
                            if padding != 4: pp += '=' * padding
                            claims = json.loads(base64.urlsafe_b64decode(pp))
                            account_id = claims.get('account_id') or claims.get('external_id')
                            if account_id:
                                return {"account_id": str(account_id), "jwt_token": jwt_token,
                                        "region": str(claims.get('lock_region') or '').upper()}
                    except Exception:
                        pass
        if resp is not None and resp.status_code == 200:
            _diagnostic('  [GUEST] MajorLogin: response could not be decoded.', flush=True)
        return {"account_id": "N/A", "jwt_token": ""}
    except Exception as exc:
        _diagnostic(f"  [GUEST] MajorLogin: {type(exc).__name__}.", flush=True)
        return {"account_id": "N/A", "jwt_token": ""}

def force_region_bind(region, jwt_token):
    try:
        url = ("https://loginbp.common.ggbluefox.com/ChooseRegion" if region.upper() in ["ME","TH"] else "https://loginbp.ppmainecoonghj.com/ChooseRegion")
        region_code = "RU" if region.upper() == "CIS" else region.upper()
        encrypted = encrypt_api(build_proto({1: region_code}).hex())
        dev = get_thread_device()
        headers = _merge_headers({
            "User-Agent": "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)",
            "Accept": "*/*", "Accept-Encoding": "deflate, gzip", "X-Ga-Sv": "1789534056", "Authorization": f"Bearer {jwt_token}",
            "X-Ga": "v1 1", "Releaseversion": RELEASE_VER, "Content-Type": "application/x-www-form-urlencoded", "X-Unity-Version": "2018.4.12f1"
        }, device=dev)
        response = request_retry('POST', url, tag="ForceRegionBind", data=bytes.fromhex(encrypted), headers=headers)
        return response.status_code if response is not None else None
    except Exception:
        return None

