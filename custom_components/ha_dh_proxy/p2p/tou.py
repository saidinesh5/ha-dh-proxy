"""
TOU framing and TCP-relay channel implementation.
Ported from dh-fwd/core/tou.go and dh-fwd/core/tcp_relay.go.
"""
import socket
import struct
import threading
import time
from typing import Callable, Optional

from .crypto import DHResponse, build_dh_request, next_cseq_for
from .profile import AppProfile

TOU_TYPE_DATA = 0x00
TOU_TYPE_SYN = 0x01
TOU_TYPE_ACK = 0x02
TOU_TYPE_KA = 0x03
TOU_TYPE_SRV = 0x04

TOU_VERSION_NIBBLE = 0x10
TOU_HDR_SIZE = 12
TOU_SYN_SIZE = 20
TOU_ACK_SIZE = 16
TOU_MAX_DATA_LEN = 0xFFFF
TOU_MAX_PACKET_LEN = 0x10000


def tou_header(typ: int) -> int:
    return TOU_VERSION_NIBBLE | (typ & 0x0F)


def tou_build_syn(session: int, port: int = 0) -> bytes:
    buf = bytearray(TOU_SYN_SIZE)
    buf[0] = tou_header(TOU_TYPE_SYN)
    struct.pack_into("!I", buf, 4, session & 0xFFFFFFFF)
    if port != 0:
        struct.pack_into("!H", buf, 14, port & 0xFFFF)
        buf[16] = 0x7F
        buf[19] = 0x01
    return bytes(buf)


def tou_build_ack(session: int, value: int = 0) -> bytes:
    buf = bytearray(TOU_ACK_SIZE)
    buf[0] = tou_header(TOU_TYPE_ACK)
    struct.pack_into("!I", buf, 4, session & 0xFFFFFFFF)
    struct.pack_into("!I", buf, 12, value & 0xFFFFFFFF)
    return bytes(buf)


def tou_build_data(session: int, payload: bytes) -> bytes:
    if len(payload) > TOU_MAX_DATA_LEN:
        raise ValueError(f"tou payload too large: {len(payload)}")
    buf = bytearray(TOU_HDR_SIZE + len(payload))
    buf[0] = tou_header(TOU_TYPE_DATA)
    struct.pack_into("!H", buf, 2, len(payload))
    struct.pack_into("!I", buf, 4, session & 0xFFFFFFFF)
    buf[TOU_HDR_SIZE:] = payload
    return bytes(buf)


def tou_build_keepalive(session: int) -> bytes:
    buf = bytearray(TOU_HDR_SIZE)
    buf[0] = tou_header(TOU_TYPE_KA)
    struct.pack_into("!I", buf, 4, session & 0xFFFFFFFF)
    return bytes(buf)


def tou_fixed_len(first_byte: int) -> tuple[int, bool]:
    if (first_byte & 0xF0) != TOU_VERSION_NIBBLE:
        return 0, False
    t = first_byte & 0x0F
    if t == TOU_TYPE_SYN:
        return TOU_SYN_SIZE, True
    if t == TOU_TYPE_ACK:
        return TOU_ACK_SIZE, True
    if t in (TOU_TYPE_KA, TOU_TYPE_SRV):
        return TOU_HDR_SIZE, True
    return 0, False


def parse_tou_packet(frame: bytes) -> tuple[int, int, Optional[bytes], int]:
    """
    Parse one complete TOU frame.
    Returns (typ, session, payload, total_len).
    """
    if len(frame) < 1:
        raise ValueError("tou buffer truncated")
    if (frame[0] & 0xF0) != TOU_VERSION_NIBBLE:
        raise ValueError("invalid tou message, wrong version")
    typ = frame[0] & 0x0F
    if typ == TOU_TYPE_DATA:
        if len(frame) < TOU_HDR_SIZE:
            raise ValueError("tou buffer truncated")
        n = struct.unpack("!H", frame[2:4])[0]
        total = TOU_HDR_SIZE + n
        if total > TOU_MAX_PACKET_LEN:
            raise ValueError(f"tou packet too large: {total}")
        if len(frame) < total:
            raise ValueError("tou buffer truncated")
        session = struct.unpack("!I", frame[4:8])[0]
        return typ, session, frame[TOU_HDR_SIZE:total], total
    if typ == TOU_TYPE_SYN:
        if len(frame) < TOU_SYN_SIZE:
            raise ValueError("tou buffer truncated")
        session = struct.unpack("!I", frame[4:8])[0]
        return typ, session, None, TOU_SYN_SIZE
    if typ == TOU_TYPE_ACK:
        if len(frame) < TOU_ACK_SIZE:
            raise ValueError("tou buffer truncated")
        session = struct.unpack("!I", frame[4:8])[0]
        return typ, session, frame[12:16], TOU_ACK_SIZE
    if typ in (TOU_TYPE_KA, TOU_TYPE_SRV):
        if len(frame) < TOU_HDR_SIZE:
            raise ValueError("tou buffer truncated")
        session = struct.unpack("!I", frame[4:8])[0]
        return typ, session, None, TOU_HDR_SIZE
    raise ValueError("invalid tou message, unknown type")


class TOUChannel:
    """TCP-relay session channel speaking TOU framing over TCP."""

    def __init__(
        self,
        sock: socket.socket,
        local_session: int,
        debug: bool = False,
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.sock = sock
        self.local_session = local_session
        self.debug = debug
        self.log_fn = log_fn or (lambda _m: None)
        self._write_lock = threading.Lock()
        self.closed = False
        self.last_recv = time.monotonic()

    @classmethod
    def dial(
        cls,
        prof: AppProfile,
        agent_host: str,
        agent_port: int,
        token: str,
        remote_port: int = 80,
        debug: bool = False,
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> "TOUChannel":
        import os

        log = log_fn or (lambda _m: None)
        log(f"tcp-relay: dialing agent {agent_host}:{agent_port}")
        sock = socket.create_connection((agent_host, agent_port), timeout=4.0)
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        my_cseq = next_cseq_for(prof)
        bind_body = f"<body><Token>{token}</Token></body>"
        req = build_dh_request(
            "POST",
            "/tcprelay/client-bind",
            bind_body,
            True,
            my_cseq,
            prof,
            "",
            False,
        )
        sock.settimeout(15.0)
        sock.sendall(req)

        # Read HTTP response headers + body
        resp = cls._read_http_response(sock)
        log(f"tcp-relay: <<< bind status={resp.code} {resp.status}")

        local_session = struct.unpack("!I", os.urandom(4))[0]
        syn = tou_build_syn(local_session, remote_port)
        sock.sendall(syn)

        ch = cls(sock=sock, local_session=local_session, debug=debug, log_fn=log)
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            typ, session, _pl, _tot = ch.read_frame(timeout=max(0.5, deadline - time.monotonic()))
            if typ == TOU_TYPE_ACK:
                log(f"tcp-relay: <<< ACK session={session:#010x} — channel up")
                ch.last_recv = time.monotonic()
                return ch
        sock.close()
        raise TimeoutError("tcp-relay ACK wait timed out")

    @staticmethod
    def _read_http_response(sock: socket.socket) -> DHResponse:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(1)
            if not chunk:
                raise ConnectionError("EOF reading TCP relay HTTP response")
            buf.extend(chunk)
        head_text = buf.decode("utf-8", errors="replace")
        lines = head_text.split("\r\n")
        parts = lines[0].split(" ", 2)
        code = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        status = parts[2] if len(parts) > 2 else ""
        content_len = 0
        for line in lines[1:]:
            if line.lower().startswith("content-length:"):
                try:
                    content_len = int(line.split(":", 1)[1].strip())
                except ValueError:
                    content_len = 0
        rem = content_len
        while rem > 0:
            chunk = sock.recv(rem)
            if not chunk:
                break
            rem -= len(chunk)
        return DHResponse(code=code, status=status)

    def _recv_exact(self, n: int, timeout: float) -> bytes:
        self.sock.settimeout(timeout)
        buf = bytearray()
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                raise ConnectionError("EOF on TOU TCP channel")
            buf.extend(chunk)
        return bytes(buf)

    def read_frame(self, timeout: float = 10.0) -> tuple[int, int, Optional[bytes], int]:
        head4 = self._recv_exact(4, timeout)
        fixed, is_fixed = tou_fixed_len(head4[0])
        if is_fixed:
            need = fixed
        elif (head4[0] & 0x0F) == TOU_TYPE_DATA:
            n = struct.unpack("!H", head4[2:4])[0]
            need = TOU_HDR_SIZE + n
            if need > TOU_MAX_PACKET_LEN:
                raise ValueError(f"tou packet too large: {need}")
        else:
            raise ValueError(f"invalid tou frame header: 0x{head4[0]:02x}")
        rest = self._recv_exact(need - 4, timeout)
        typ, session, payload, total = parse_tou_packet(head4 + rest)
        self.last_recv = time.monotonic()
        return typ, session, payload, total

    def write(self, frame: bytes) -> None:
        with self._write_lock:
            if self.closed:
                raise ConnectionError("tou channel closed")
            self.sock.settimeout(10.0)
            self.sock.sendall(frame)

    def write_data(self, session: int, payload: bytes) -> None:
        self.write(tou_build_data(session, payload))

    def write_ack(self, session: int, value: int = 0) -> None:
        self.write(tou_build_ack(session, value))

    def write_keepalive(self, session: int) -> None:
        self.write(tou_build_keepalive(session))

    def close(self) -> None:
        with self._write_lock:
            if self.closed:
                return
            self.closed = True
            try:
                self.sock.close()
            except Exception:
                pass
