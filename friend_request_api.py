"""Minimal NGGL friend-confirm API helper; intentionally avoids importing nggl_core.

This keeps the BR worker's protobuf descriptors isolated while reusing the
legacy ConfirmFriendRequest encryption and protobuf field layout.
"""
import httpx
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from urllib.parse import urlsplit

AES_KEY = b'Yg&tc%DEuh6%Zc^8'
AES_IV  = b'6oyZDr22E3ychjM%'

def _encode_varint(value):
    value = int(value)
    if value < 0:
        value &= 0xFFFFFFFFFFFFFFFF
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)

def create_proto(fields):
    """Encode scalar integer fields using the legacy NGGL protobuf wire format."""
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(field, str):
            field = int(field)
        if isinstance(value, bool):
            value = int(value)
        if not isinstance(value, int):
            raise TypeError("friend confirmation only supports integer fields")
        packet.extend(_encode_varint((field << 3) | 0))
        packet.extend(_encode_varint(value))
    return bytes(packet)

def encrypt_api(plain_hex):
    return AES.new(AES_KEY, AES.MODE_CBC, AES_IV).encrypt(
        pad(bytes.fromhex(plain_hex), AES.block_size)).hex()

async def confirm_friend_request(target_id, account_data, tag="MAIN"):
    """Confirm one incoming friend request with verified HTTPS and no redirects."""
    if not isinstance(account_data, dict):
        return False
    try:
        target_id = int(target_id)
        own_id = int(account_data.get("account_id"))
    except (TypeError, ValueError, OverflowError):
        return False
    target_text = str(target_id)
    own_text = str(own_id)
    if (not target_text.isdigit() or not (6 <= len(target_text) <= 15)
            or not own_text.isdigit() or not (6 <= len(own_text) <= 15)
            or target_id == own_id):
        return False

    jwt = account_data.get("token")
    server_url = account_data.get("server_url")
    release_version = account_data.get("release_version")
    if not all(isinstance(value, str) and value.strip()
               for value in (jwt, server_url, release_version)):
        return False
    jwt = jwt.strip()
    server_url = server_url.strip()
    release_version = release_version.strip()
    try:
        parts = urlsplit(server_url)
        if (parts.scheme.lower() != "https" or not parts.netloc
                or parts.username or parts.password or parts.query or parts.fragment):
            return False
        base = f"{parts.scheme.lower()}://{parts.netloc}{parts.path.rstrip('/')}"
        url = f"{base}/ConfirmFriendRequest"
        payload = bytes.fromhex(encrypt_api(create_proto(
            {"1": target_id, "2": own_id}).hex()))
        headers = {
            "authorization": f"Bearer {jwt}",
            "host": parts.netloc,
            "x-ga": "v1 1", "content-type": "application/x-www-form-urlencoded",
            "accept-encoding": "deflate, gzip", "releaseversion": release_version,
            "user-agent": "UnityPlayer/2022.3.47f1", "accept": "*/*",
            "x-unity-version": "2022.3.47f1",
        }
        # Do not forward a bearer token to an unverified endpoint or redirect.
        async with httpx.AsyncClient(timeout=8.0, follow_redirects=False) as session:
            response = await session.post(url, headers=headers, content=payload)
        if response.status_code == 200 and response.content:
            return True
    except Exception:
        return False
    return False
