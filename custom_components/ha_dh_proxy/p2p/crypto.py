"""
Cryptographic and DH HTTP-over-UDP serialization helpers.
Ported from dh-fwd/core/helpers.go and dh-fwd/core/tunnel.go.
Zero external dependencies (uses stdlib hashlib, hmac, base64, xml.etree.ElementTree, and py_dh_p2p.aes).
"""
import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import random
import socket
import struct
import threading
import time
from typing import Optional
import xml.etree.ElementTree as ET

from .aes import aes256_ofb_crypt
from .profile import (
    AppProfile,
    SMARTPSS_PROFILE,
    now_adjusted,
    random_hex,
)

DEFAULT_SALT = ""
AES_IV = b"2z52*lk9o6HRyJrf"
DEVINFO_KEY = b"kRjmsUB&ezmdGLL67H#$ojw@XflcaIaf"
DEVINFO_IV = b"MydvJw*Iw1w&i^kk"

_cseq_lock = threading.Lock()
_cseq_counter: int = 0


def next_cseq() -> int:
    global _cseq_counter
    with _cseq_lock:
        _cseq_counter = (_cseq_counter + 1) & 0xFFFFFFFF
        return _cseq_counter


def get_nonce() -> int:
    """Random signed int32 (-2^31 .. 2^31 - 1)."""
    return random.randint(-(1 << 31), (1 << 31) - 1)


def next_cseq_for(prof: AppProfile) -> int:
    if prof.random_cseq:
        return get_nonce() & 0xFFFFFFFF
    return next_cseq()


def to_signed_int32(val: int) -> int:
    val &= 0xFFFFFFFF
    return val - 0x100000000 if (val & 0x80000000) else val


def wsse_digest(nonce: str, created: str, user: str, userkey: str) -> str:
    raw = f"{nonce}{created}DHP2P:{user}:{userkey}".encode("utf-8")
    return base64.b64encode(hashlib.sha1(raw).digest()).decode("ascii")


def get_derive_key(username: str, password: str, randsalt: str = "") -> bytes:
    salt = randsalt if randsalt else DEFAULT_SALT
    raw = f"{username}:Login to {salt}:{password}".encode("utf-8")
    return hashlib.md5(raw).hexdigest().upper().encode("ascii")


def derive_dk(key: bytes, nonce: int) -> bytes:
    salt = str(nonce).encode("ascii")
    return hashlib.pbkdf2_hmac("sha256", key, salt, 20000, 32)


def get_enc(key: bytes, nonce: int, data: str) -> str:
    dk = derive_dk(key, nonce)
    ct = aes256_ofb_crypt(dk, AES_IV, data.encode("utf-8"))
    return base64.b64encode(ct).decode("ascii")


def get_dec(key: bytes, nonce: int, data: str) -> str:
    try:
        raw = base64.b64decode(data)
    except Exception:
        return data
    dk = derive_dk(key, nonce)
    pt = aes256_ofb_crypt(dk, AES_IV, raw)
    return pt.decode("utf-8", errors="replace")


def get_auth_at(
    username: str,
    key: bytes,
    nonce: int,
    payload: str,
    randsalt: str,
    created: int,
) -> str:
    salt = randsalt if randsalt else DEFAULT_SALT
    msg = f"{nonce}{created}{payload}".encode("utf-8")
    mac = hmac.new(key, msg, hashlib.sha256).digest()
    auth = base64.b64encode(mac).decode("ascii")
    return (
        f"<CreateDate>{created}</CreateDate>"
        f"<DevAuth>{auth}</DevAuth>"
        f"<Nonce>{nonce}</Nonce>"
        f"<RandSalt>{salt}</RandSalt>"
        f"<UserName>{username}</UserName>"
    )


def get_auth(
    username: str,
    key: bytes,
    nonce: int,
    payload: str,
    randsalt: str,
) -> str:
    created = int(now_adjusted().timestamp())
    return get_auth_at(username, key, nonce, payload, randsalt, created)


def decrypt_dev_info(field_b64: str) -> bytes:
    raw = base64.b64decode(field_b64.strip())
    return aes256_ofb_crypt(DEVINFO_KEY, DEVINFO_IV, raw)


def parse_device_info_json(field_b64: str) -> dict:
    if not field_b64:
        return {}
    try:
        pt = decrypt_dev_info(field_b64)
        # Strip trailing NULs or whitespace if present
        text = pt.decode("utf-8", errors="ignore").strip("\x00 \t\r\n")
        return json.loads(text)
    except Exception:
        return {}


def build_dh_request(
    method: str,
    path: str,
    body: str = "",
    auth: bool = True,
    my_cseq: int = 1,
    prof: Optional[AppProfile] = None,
    pcs_id: str = "",
    warmup: bool = False,
) -> bytes:
    if prof is None:
        prof = SMARTPSS_PROFILE

    nonce_str = str(get_nonce())
    curdate = prof.created_now()
    digest = wsse_digest(nonce_str, curdate, prof.wsse_user, prof.wsse_user_key)

    auth_block = ""
    if auth:
        auth_block = (
            'Authorization: WSSE profile="UsernameToken"\r\n'
            f'X-WSSE: UsernameToken Username="{prof.wsse_user}", '
            f'PasswordDigest="{digest}", Nonce="{nonce_str}", Created="{curdate}"\r\n'
        )

    parts: list[str] = []
    if prof.app_header_order:
        parts.append(f"{method} {path} HTTP/1.1\r\n")
        if not warmup:
            if prof.version:
                parts.append(f"X-Version: {prof.version}\r\n")
            if prof.sversion:
                parts.append(f"X-Sversion: {prof.sversion}\r\n")
        if pcs_id:
            parts.append(f"x-pcs-request-id: {pcs_id}\r\n")
        if prof.to_u_type:
            parts.append(f"X-ToUType: {prof.to_u_type}\r\n")
        parts.append(f"CSeq: {to_signed_int32(my_cseq)}\r\n")
        parts.append(auth_block)
    else:
        parts.append(f"{method} {path} HTTP/1.1\r\nCSeq: {my_cseq & 0xFFFFFFFF}\r\n")
        parts.append(auth_block)
        if pcs_id:
            parts.append(f"x-pcs-request-id: {pcs_id}\r\n")
        if warmup:
            if prof.to_u_type:
                parts.append(f"X-ToUType: {prof.to_u_type}\r\n")
        else:
            if prof.version:
                parts.append(f"X-Version: {prof.version}\r\n")
            if prof.sversion:
                parts.append(f"X-Sversion: {prof.sversion}\r\n")
            if prof.to_u_type:
                parts.append(f"X-ToUType: {prof.to_u_type}\r\n")

    if body:
        body_bytes = body.encode("utf-8")
        parts.append(f"Content-Type: \r\nContent-Length: {len(body_bytes)}\r\n")
    parts.append(f"\r\n{body}")
    return "".join(parts).encode("utf-8")


def parse_xml_flat(xml_text: str) -> dict[str, str]:
    """Flatten an XML document into 'path/to/tag' -> text using stdlib ElementTree."""
    result: dict[str, str] = {}
    if not xml_text or not xml_text.strip():
        return result
    try:
        root = ET.fromstring(xml_text.strip())
    except ET.ParseError:
        return result

    def _walk(elem: ET.Element, stack: list[str]) -> None:
        tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        cur = stack + [tag]
        if elem.text and elem.text.strip():
            result["/".join(cur)] = elem.text.strip()
        for child in elem:
            _walk(child, cur)

    _walk(root, [])
    return result


@dataclass
class DHResponse:
    version: str = ""
    code: int = 0
    status: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    body: dict[str, str] = field(default_factory=dict)

    def header(self, name: str) -> str:
        low = name.lower()
        for k, v in self.headers.items():
            if k.lower() == low:
                return v
        return ""


def parse_dh_response(data: str) -> DHResponse:
    parts = data.split("\r\n\r\n", 1)
    head_part = parts[0]
    body_part = parts[1].strip() if len(parts) > 1 else ""

    lines = head_part.split("\r\n")
    status_parts = lines[0].split(" ", 2)
    version = status_parts[0] if status_parts else ""
    code = 0
    if len(status_parts) > 1:
        try:
            code = int(status_parts[1])
        except ValueError:
            code = 0
    status = status_parts[2] if len(status_parts) > 2 else ""

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ": " in line:
            k, v = line.split(": ", 1)
            headers[k] = v

    body = parse_xml_flat(body_part) if body_part else {}
    return DHResponse(version=version, code=code, status=status, headers=headers, body=body)


def build_local_addr(prefixes: list[str], bind_ip: str, lport: int) -> str:
    last = f"{bind_ip}:{lport}"
    if not prefixes:
        return f"{bind_ip},{last}"
    return ",".join(prefixes) + "," + last


def get_host_ipv4_prefixes(bind_ip: str) -> list[str]:
    out: list[str] = []
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127.") and not ip.startswith("169.254.") and ip != "0.0.0.0" and ip != bind_ip:
                if ip not in out:
                    out.append(ip)
    except Exception:
        pass
    return out


def invert_bytes(data: bytes) -> bytes:
    return bytes(b ^ 0xFF for b in data)


def ip_port_to_inverted_bytes(ip_port: str) -> bytes:
    ip_str, port_str = ip_port.split(":", 1)
    port = int(port_str)
    raw = struct.pack("!H", port) + socket.inet_aton(ip_str)
    return invert_bytes(raw)


@dataclass
class ChannelRequest:
    prof: AppProfile
    dtype: int
    username: str = ""
    password: str = ""
    randsalt: str = ""
    identify: str = ""
    bind_ip: str = "127.0.0.1"
    lport: int = 50000
    addr_prefixes: list[str] = field(default_factory=list)
    client_id: str = ""
    pcs_id: str = ""
    cseq: int = 0
    created: int = 0
    nonce: int = 0
    key: bytes = b""
    laddr_enc: str = ""

    @classmethod
    def create(
        cls,
        prof: AppProfile,
        dtype: int,
        username: str,
        password: str,
        randsalt: str,
        aid: bytes,
        bind_ip: str,
        lport: int,
        fwd_port: int = 554,
        addr_prefixes: Optional[list[str]] = None,
    ) -> "ChannelRequest":
        identify = " ".join(f"{b:x}" for b in aid)
        if addr_prefixes is None:
            addr_prefixes = get_host_ipv4_prefixes(bind_ip)
        port_tag = fwd_port if fwd_port > 0 else 37777
        client_id = f"{port_tag}_{random_hex(8)}" if prof.extended_body else ""
        pcs_id = random_hex(8) if prof.pcs_request_id else ""
        cseq = next_cseq_for(prof)
        created = int(now_adjusted().timestamp())
        nonce = get_nonce()
        key = get_derive_key(username, password, randsalt) if dtype > 0 else b""
        inst = cls(
            prof=prof,
            dtype=dtype,
            username=username,
            password=password,
            randsalt=randsalt,
            identify=identify,
            bind_ip=bind_ip,
            lport=lport,
            addr_prefixes=addr_prefixes,
            client_id=client_id,
            pcs_id=pcs_id,
            cseq=cseq,
            created=created,
            nonce=nonce,
            key=key,
        )
        if dtype > 0:
            inst.laddr_enc = get_enc(inst.key, inst.nonce, inst.local_addr())
        return inst

    def local_addr(self) -> str:
        return build_local_addr(self.addr_prefixes, self.bind_ip, self.lport)

    def regenerate(self) -> None:
        self.nonce = get_nonce()
        if self.dtype > 0:
            self.laddr_enc = get_enc(self.key, self.nonce, self.local_addr())

    def body(self) -> str:
        encrypt_tag = "<IpEncrpt>true</IpEncrpt>"
        laddr_tag = f"<LocalAddr>{self.local_addr()}</LocalAddr>"
        auth_str = ""
        if self.dtype > 0:
            encrypt_tag = "<IpEncrptV2>true</IpEncrptV2>"
            laddr_tag = f"<LocalAddr>{self.laddr_enc}</LocalAddr>"
            auth_str = get_auth_at(
                self.username,
                self.key,
                self.nonce,
                self.laddr_enc,
                self.randsalt,
                self.created,
            )

        out = ["<body>", auth_str, f"<Identify>{self.identify}</Identify>", encrypt_tag]
        if self.prof.extended_body:
            out.append(
                f"<NatValueT>0</NatValueT><version>{self.prof.version}</version><sVersion>{self.prof.sversion}</sVersion>"
            )
            out.append(laddr_tag)
            out.append(f"<Pid>0</Pid><ClientId>{self.client_id}</ClientId>")
        else:
            out.append(laddr_tag)
            out.append("<version>5.0.0</version>")
        out.append("</body>")
        return "".join(out)
