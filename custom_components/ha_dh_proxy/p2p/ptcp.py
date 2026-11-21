"""
PTCP transport framing and realm payload helpers.
Ported from dh-fwd/core/helpers.go and dh-fwd/core/tunnel.go.
"""
from dataclasses import dataclass, field
import struct
import time

PTCP_SYNC_BODY = b"\x00\x03\x01\x00"
PTCP_HEARTBEAT_BODY = b"\x13\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"

PTCP_TYPE_DATA = 0x10
PTCP_TYPE_BIND = 0x11
PTCP_TYPE_STATUS = 0x12
PTCP_TYPE_HEARTBEAT = 0x13
PTCP_TYPE_PAUSE = 0x17
PTCP_TYPE_PAUSE_ACK = 0x18
PTCP_TYPE_RESUME = 0x19
PTCP_TYPE_RESUME_ACK = 0x1A


@dataclass
class PTCPPayload:
    realm: int
    payload: bytes

    def to_bytes(self) -> bytes:
        length = len(self.payload) | 0x10000000
        return struct.pack("!III", length, self.realm & 0xFFFFFFFF, 0) + self.payload

    @classmethod
    def parse(cls, data: bytes) -> "PTCPPayload":
        if len(data) < 12:
            raise ValueError("PTCPPayload packet too short")
        hdr_len, realm, _pad = struct.unpack("!III", data[:12])
        length = hdr_len & 0xFFFF
        body = data[12:]
        if length > 0 and len(body) >= length:
            body = body[:length]
        return cls(realm=realm, payload=body)


def build_ptcp_bind(realm_id: int, remote_port: int) -> bytes:
    """20-byte PTCP BIND (0x11) frame for `remote_port` on 127.0.0.1."""
    buf = bytearray(20)
    buf[0] = PTCP_TYPE_BIND
    struct.pack_into("!I", buf, 4, realm_id & 0xFFFFFFFF)
    struct.pack_into("!I", buf, 12, remote_port & 0xFFFFFFFF)
    buf[16] = 0x7F
    buf[19] = 0x01
    return bytes(buf)


def build_ptcp_disc(realm_id: int) -> bytes:
    """16-byte PTCP DISC (0x12) frame for `realm_id`."""
    return (
        b"\x12\x00\x00\x00"
        + struct.pack("!I", realm_id & 0xFFFFFFFF)
        + b"\x00\x00\x00\x00"
        + b"DISC"
    )


@dataclass
class PTCP:
    rlid: int
    llid: int
    pid: int
    lmid: int
    rmid: int
    body: bytes = b""

    def to_bytes(self) -> bytes:
        return (
            struct.pack(
                "!4sIIIII",
                b"PTCP",
                self.rlid & 0xFFFFFFFF,
                self.llid & 0xFFFFFFFF,
                self.pid & 0xFFFFFFFF,
                self.lmid & 0xFFFFFFFF,
                self.rmid & 0xFFFFFFFF,
            )
            + self.body
        )

    @classmethod
    def parse(cls, data: bytes) -> "PTCP":
        if len(data) < 24:
            raise ValueError("PTCP packet too short")
        magic, rlid, llid, pid, lmid, rmid = struct.unpack("!4sIIIII", data[:24])
        if magic != b"PTCP":
            raise ValueError("Invalid PTCP magic")
        return cls(rlid=rlid, llid=llid, pid=pid, lmid=lmid, rmid=rmid, body=data[24:])


@dataclass
class PTCPSegment:
    seq: int
    end_seq: int
    raw: bytes
    sent_at: float = field(default_factory=time.monotonic)
    retries: int = 0
