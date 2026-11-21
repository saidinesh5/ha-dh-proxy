"""
Core Dahua / CP Plus P2P UDP transport, cloud handshake, NAT traversal, and TCP port forwarding tunnel.
Ported from dh-fwd/core/helpers.go and dh-fwd/core/tunnel.go.
"""
from dataclasses import dataclass, field
import os
import socket
import struct
import threading
import time
from typing import Callable, Optional

from .crypto import (
    ChannelRequest,
    DHResponse,
    build_dh_request,
    get_auth,
    get_dec,
    get_nonce,
    invert_bytes,
    next_cseq_for,
    parse_device_info_json,
    parse_dh_response,
)
from .profile import (
    AppProfile,
    SMARTPSS_PROFILE,
    profile_fallback_order,
)
from .ptcp import (
    PTCP,
    PTCP_HEARTBEAT_BODY,
    PTCP_SYNC_BODY,
    PTCP_TYPE_DATA,
    PTCP_TYPE_HEARTBEAT,
    PTCP_TYPE_PAUSE,
    PTCP_TYPE_PAUSE_ACK,
    PTCP_TYPE_RESUME,
    PTCP_TYPE_RESUME_ACK,
    PTCP_TYPE_STATUS,
    PTCPPayload,
    PTCPSegment,
    build_ptcp_bind,
    build_ptcp_disc,
)
from .tou import (
    TOU_TYPE_ACK,
    TOU_TYPE_DATA,
    TOU_TYPE_KA,
    TOU_TYPE_SRV,
    TOU_TYPE_SYN,
    TOUChannel,
    tou_build_syn,
)

BIND_TIMEOUT = 10.0
RELAY_READ_TIMEOUT = 15.0
HEARTBEAT_TIMEOUT = 30.0
DATA_SEGMENT_MAX = 1280


class DeviceNotFoundError(RuntimeError):
    pass


class DeviceAuthError(RuntimeError):
    pass


@dataclass
class PortSpec:
    local: int
    remote: int


def parse_port_spec(spec_str: str) -> list[PortSpec]:
    """
    Parse dh-fwd port specification:
      - "8554:554" -> [PortSpec(8554, 554)]
      - "8554,8080:554,80" -> [PortSpec(8554, 554), PortSpec(8080, 80)]
      - "554" -> [PortSpec(0, 554)]
    """
    spec_str = (spec_str or "").strip()
    if not spec_str:
        return [PortSpec(local=554, remote=554)]

    def _expand(part: str) -> list[int]:
        ports: list[int] = []
        for token in part.split(","):
            token = token.strip()
            if not token:
                continue
            if "-" in token:
                lo_s, hi_s = token.split("-", 1)
                lo, hi = int(lo_s), int(hi_s)
                if lo > hi or lo < 0 or hi > 65535:
                    raise ValueError(f"invalid port range: {token}")
                ports.extend(range(lo, hi + 1))
            else:
                p = int(token)
                if p < 0 or p > 65535:
                    raise ValueError(f"invalid port: {p}")
                ports.append(p)
        return ports

    if ":" not in spec_str:
        remotes = _expand(spec_str)
        return [PortSpec(local=0, remote=r) for r in remotes]

    local_part, remote_part = spec_str.split(":", 1)
    locals_list = _expand(local_part)
    remotes_list = _expand(remote_part)
    if len(locals_list) == len(remotes_list):
        return [PortSpec(local=l, remote=r) for l, r in zip(locals_list, remotes_list)]
    if len(remotes_list) == 1 and len(locals_list) > 1:
        return [PortSpec(local=l, remote=remotes_list[0]) for l in locals_list]
    raise ValueError(f"mismatched local/remote port counts in '{spec_str}'")


class UDP:
    """
    UDP transport speaking both Level-1 DH/NF HTTP signaling and Level-3 PTCP.
    """

    def __init__(
        self,
        host: str,
        port: int,
        debug: bool = False,
        profile: Optional[AppProfile] = None,
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.profile = profile or SMARTPSS_PROFILE
        self.debug = debug
        self.log_fn = log_fn or (lambda msg: print(msg) if self.debug else None)
        self.rhost = host
        self.rport = port
        self.raddr: Optional[tuple[str, int]] = None

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2 * 1024 * 1024)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1 * 1024 * 1024)
        except Exception:
            pass
        self.sock.bind(("0.0.0.0", 0))
        self.lhost, self.lport = self.sock.getsockname()

        self.bind_ip = "127.0.0.1"
        if host:
            try:
                resolved_ip = socket.gethostbyname(host)
                self.raddr = (resolved_ip, port)
                probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                try:
                    probe.connect((resolved_ip, port))
                    self.bind_ip = probe.getsockname()[0]
                finally:
                    probe.close()
            except Exception:
                self.raddr = (host, port)

        self._rx_lock = threading.Lock()
        self._ptcp_lock = threading.Lock()
        self.ptcp_sent: int = 0
        self.ptcp_recv: int = 0
        self.ptcp_count: int = 0
        self.ptcp_id: int = 0
        self.rmid: int = 0

        self.rcv_nxt: int = 0
        self.rcv_ooo: dict[int, PTCP] = {}
        self.rcv_ready: list[PTCP] = []

        self.ptcp_segments: list[PTCPSegment] = []
        self.peer_ack: int = 0
        self.last_ack_seen: int = 0
        self.dup_ack_count: int = 0
        self.srtt: float = 0.0
        self.rttvar: float = 0.0
        self.rto: float = 0.25

        self.last_recv: float = time.monotonic()

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass

    def set_remote(self, host: str, port: int) -> None:
        self.rhost = host
        self.rport = port
        try:
            self.raddr = (socket.gethostbyname(host), port)
        except Exception:
            self.raddr = (host, port)

    def send(self, data: bytes) -> None:
        if self.raddr is not None:
            try:
                self.sock.sendto(data, self.raddr)
            except Exception:
                pass

    def send_to(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            self.sock.sendto(data, addr)
        except Exception:
            pass

    def recv(self, bufsize: int = 65535, timeout: Optional[float] = None) -> bytes:
        data, _ = self.recv_from(bufsize=bufsize, timeout=timeout)
        return data

    def recv_from(
        self, bufsize: int = 65535, timeout: Optional[float] = None
    ) -> tuple[bytes, tuple[str, int]]:
        with self._rx_lock:
            self.sock.settimeout(timeout)
            data, addr = self.sock.recvfrom(bufsize)
            self.last_recv = time.monotonic()
            return data, addr

    def read(
        self, return_error: bool = False, timeout: float = RELAY_READ_TIMEOUT
    ) -> DHResponse:
        data = self.recv(4096, timeout=timeout)
        text = data.decode("utf-8", errors="replace")
        if self.debug:
            self.log_fn(f":{self.lport} <<< {self.rhost}:{self.rport}\n{text}")
        res = parse_dh_response(text)
        if not return_error and res.code >= 400:
            raise RuntimeError(f"error {res.code}: {res.status}")
        return res

    def request_ex(
        self,
        path: str,
        body: str = "",
        auth: bool = True,
        should_read: bool = True,
        verb: str = "",
        cseq: int = 0,
        pcs_id: str = "",
        warmup: bool = False,
        timeout: float = RELAY_READ_TIMEOUT,
    ) -> Optional[DHResponse]:
        my_cseq = cseq if cseq != 0 else next_cseq_for(self.profile)
        method = verb or (self.profile.verb_post if body else self.profile.verb_get)
        req = build_dh_request(
            method=method,
            path=path,
            body=body,
            auth=auth,
            my_cseq=my_cseq,
            prof=self.profile,
            pcs_id=pcs_id,
            warmup=warmup,
        )
        if self.debug:
            self.log_fn(
                f":{self.lport} >>> {self.rhost}:{self.rport}\n{req.decode('utf-8', errors='replace')}"
            )
        self.send(req)
        if should_read:
            return self.read(return_error=False, timeout=timeout)
        return None

    def request(
        self, path: str, body: str = "", auth: bool = True, should_read: bool = True
    ) -> Optional[DHResponse]:
        return self.request_ex(path=path, body=body, auth=auth, should_read=should_read)

    def request_ptcp(self, body: bytes = b"") -> None:
        with self._ptcp_lock:
            is_sync = body == PTCP_SYNC_BODY
            pid = 0x0002FFFF if is_sync else 0x0000FFFF
            ptcp = PTCP(
                rlid=self.ptcp_sent,
                llid=self.ptcp_recv,
                pid=pid,
                lmid=self.ptcp_id,
                rmid=self.rmid,
                body=body,
            )
            raw = ptcp.to_bytes()
            self.ptcp_sent = (self.ptcp_sent + len(body)) & 0xFFFFFFFF
            self.ptcp_id = (self.ptcp_id + 1) & 0xFFFFFFFF
            if not is_sync and len(body) > 0:
                self.ptcp_count += 1
                if len(self.ptcp_segments) < 64:
                    self.ptcp_segments.append(
                        PTCPSegment(
                            seq=ptcp.rlid,
                            end_seq=self.ptcp_sent,
                            raw=raw,
                            sent_at=time.monotonic(),
                        )
                    )
            self.send(raw)

    def read_ptcp(self, timeout: float = 0.25) -> PTCP:
        with self._ptcp_lock:
            if self.rcv_ready:
                return self.rcv_ready.pop(0)

        deadline = time.monotonic() + timeout
        while True:
            rem = deadline - time.monotonic()
            if rem <= 0:
                with self._ptcp_lock:
                    if self.rcv_ooo:
                        min_seq = min(self.rcv_ooo.keys())
                        seg = self.rcv_ooo.pop(min_seq)
                        self.rcv_nxt = (min_seq + len(seg.body)) & 0xFFFFFFFF
                        self.ptcp_recv = self.rcv_nxt
                        while self.rcv_nxt in self.rcv_ooo:
                            nxt = self.rcv_ooo.pop(self.rcv_nxt)
                            self.rcv_nxt = (self.rcv_nxt + len(nxt.body)) & 0xFFFFFFFF
                            self.ptcp_recv = self.rcv_nxt
                            self.rcv_ready.append(nxt)
                        return seg
                raise socket.timeout("read_ptcp timed out")

            data = self.recv(4096, timeout=rem)
            try:
                ptcp = PTCP.parse(data)
            except ValueError:
                continue

            with self._ptcp_lock:
                self.rmid = ptcp.lmid
                if ptcp.llid > self.peer_ack:
                    self.peer_ack = ptcp.llid

                if self.ptcp_segments:
                    remaining: list[PTCPSegment] = []
                    now = time.monotonic()
                    for seg in self.ptcp_segments:
                        if seg.end_seq > ptcp.llid:
                            remaining.append(seg)
                        elif seg.retries == 0:
                            sample = now - seg.sent_at
                            if 0 < sample < 60.0:
                                if self.srtt == 0.0:
                                    self.srtt = sample
                                    self.rttvar = sample / 2.0
                                else:
                                    diff = abs(sample - self.srtt)
                                    self.rttvar = (3.0 * self.rttvar + diff) / 4.0
                                    self.srtt = (7.0 * self.srtt + sample) / 8.0
                                self.rto = min(60.0, max(0.25, self.srtt + 4.0 * self.rttvar))
                    self.ptcp_segments = remaining

                    if ptcp.llid == self.last_ack_seen and self.ptcp_segments:
                        self.dup_ack_count += 1
                        if self.dup_ack_count == 3:
                            first = self.ptcp_segments[0]
                            if first.retries < 5:
                                first.retries += 1
                                first.sent_at = now
                                self.send(first.raw)
                    elif ptcp.llid > self.last_ack_seen:
                        self.last_ack_seen = ptcp.llid
                        self.dup_ack_count = 0

                if len(ptcp.body) == 0:
                    return ptcp

                if ptcp.rlid == self.rcv_nxt:
                    self.rcv_nxt = (self.rcv_nxt + len(ptcp.body)) & 0xFFFFFFFF
                    self.ptcp_recv = self.rcv_nxt
                    while self.rcv_nxt in self.rcv_ooo:
                        nxt = self.rcv_ooo.pop(self.rcv_nxt)
                        self.rcv_nxt = (self.rcv_nxt + len(nxt.body)) & 0xFFFFFFFF
                        self.ptcp_recv = self.rcv_nxt
                        self.rcv_ready.append(nxt)
                    return ptcp

                if ptcp.rlid > self.rcv_nxt:
                    if len(self.rcv_ooo) < 128:
                        self.rcv_ooo[ptcp.rlid] = ptcp
                    need_ack = True
                else:
                    need_ack = True

            if need_ack:
                self.request_ptcp(b"")

    def check_retransmit(self) -> int:
        with self._ptcp_lock:
            if not self.ptcp_segments:
                return 0
            now = time.monotonic()
            base_rto = max(0.25, self.rto)
            retransmitted = 0
            for seg in self.ptcp_segments:
                cur_rto = min(60.0, base_rto * (1 << seg.retries)) if seg.retries > 0 else base_rto
                if (now - seg.sent_at) >= cur_rto and seg.retries < 5:
                    seg.retries += 1
                    seg.sent_at = now
                    self.send(seg.raw)
                    retransmitted += 1
            return retransmitted


def probe_device_info(p2psrv_remote: UDP, serial: str, timeout: float = 3.0) -> dict:
    """
    Send /probe/device/<SN> and /info/device/<SN> to the device's P2P server (US),
    returning the decrypted Info JSON dict (randsalt, httpport, privport, rtspport, devP2PVersion).
    """
    try:
        p2psrv_remote.request_ex(f"/probe/device/{serial}", timeout=timeout)
    except Exception:
        pass
    try:
        p2psrv_remote.request_ex(f"/info/device/{serial}", should_read=False)
        res = p2psrv_remote.read(return_error=True, timeout=timeout)
        if res.code < 300:
            info_b64 = res.body.get("body/Info", "")
            return parse_device_info_json(info_b64)
    except Exception:
        pass
    return {}


def query_device_info(
    serial: str,
    profile: Optional[AppProfile] = None,
    debug: bool = False,
    timeout: float = 4.0,
) -> tuple[AppProfile, str, dict]:
    """
    Resolve `serial` on `profile` (or auto-discover across profile_fallback_order())
    and decrypt its /info/device/<SN> blob.
    Returns (matched_profile, us_server_addr, info_dict).
    """
    profiles = [profile] if profile is not None else profile_fallback_order()
    last_err: Optional[Exception] = None
    for prof in profiles:
        u = UDP(prof.main_server, prof.main_port, debug=debug, profile=prof)
        try:
            try:
                u.request_ex(
                    prof.warmup_path,
                    auth=prof.warmup_auth,
                    should_read=True,
                    warmup=True,
                    timeout=2.0,
                )
            except Exception:
                pass
            res = u.request_ex(
                f"/online/p2psrv/{serial}",
                auth=True,
                should_read=True,
                timeout=timeout,
            )
            us = res.body.get("body/US", "") if res else ""
            if not us or ":" not in us:
                raise DeviceNotFoundError(f"device {serial} not found on {prof.name}")
            host, port_s = us.split(":", 1)
            p2p_u = UDP(host, int(port_s), debug=debug, profile=prof)
            try:
                info = probe_device_info(p2p_u, serial, timeout=timeout)
            finally:
                p2p_u.close()
            return prof, us, info
        except Exception as exc:
            last_err = exc
        finally:
            u.close()
    raise DeviceNotFoundError(f"Failed to resolve device {serial}: {last_err}")


@dataclass
class _ClientConn:
    conn: socket.socket
    remote_port: int
    last_keepalive: float = field(default_factory=time.monotonic)
    cseq: int = 100
    closed: bool = False
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def write_data(self, data: bytes) -> None:
        with self._lock:
            if self.closed:
                return
            try:
                self.conn.sendall(data)
            except Exception:
                self.closed = True

    def close(self) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
            try:
                self.conn.close()
            except Exception:
                pass


class Tunnel:
    """
    Full Dahua / CP Plus P2P Tunnel managing cloud handshake, NAT traversal
    (STUN punch / UDP relay / TCP TOU relay), and local TCP port forwarding.
    """

    def __init__(
        self,
        serial: str,
        specs: list[PortSpec],
        profile: Optional[AppProfile] = None,
        dtype: int = 1,
        username: str = "admin",
        password: str = "",
        randsalt: str = "",
        force_relay: bool = False,
        use_tcp: bool = False,
        debug: bool = False,
        bind_address: str = "127.0.0.1",
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.serial = serial
        self.specs = [PortSpec(s.local, s.remote) for s in specs]
        self.profile = profile or SMARTPSS_PROFILE
        self.dtype = dtype
        self.username = username
        self.password = password
        self.randsalt = randsalt
        self.force_relay = force_relay
        self.use_tcp = use_tcp
        self.debug = debug
        self.bind_address = bind_address
        self.log_fn = log_fn or (lambda msg: print(f"[py-dh-p2p] {msg}") if self.debug else None)

        self.device_info: dict = {}
        self.cam_http: int = 0
        self.cam_priv: int = 0
        self.cam_rtsp: int = 0

        self.main_remote: Optional[UDP] = None
        self.device_remote: Optional[UDP] = None
        self.primary: Optional[UDP] = None
        self.tou: Optional[TOUChannel] = None
        self.use_tcp_path: bool = False
        self.is_direct: bool = False

        self.listeners: list[socket.socket] = []
        self.bound_ports: dict[int, int] = {}  # remote_port -> actual_local_port

        self._clients_lock = threading.Lock()
        self._clients: dict[int, _ClientConn] = {}
        self._bind_lock = threading.Lock()
        self._bind_waits: dict[int, threading.Event] = {}
        self._bind_req_lock = threading.Lock()

        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self.last_activity_time: float = time.monotonic()

    @property
    def active_client_count(self) -> int:
        with self._clients_lock:
            return len(self._clients)

    def touch_activity(self) -> None:
        self.last_activity_time = time.monotonic()

    def is_running(self) -> bool:
        return not self._stop_event.is_set() and (
            self.primary is not None or self.tou is not None
        )

    def establish(self) -> None:
        """Run the 4-phase dh-fwd P2P cloud handshake."""
        prof = self.profile
        main_remote = UDP(
            prof.main_server, prof.main_port, debug=self.debug, profile=prof, log_fn=self.log_fn
        )
        self.main_remote = main_remote

        # Phase 1: Cloud discovery
        self.log_fn(f"[{prof.name}] Phase 1: cloud lookup on {prof.main_server}:{prof.main_port}")
        try:
            main_remote.request_ex(
                prof.warmup_path,
                auth=prof.warmup_auth,
                should_read=True,
                warmup=True,
                timeout=3.0,
            )
        except Exception:
            pass

        res = main_remote.request_ex(
            f"/online/p2psrv/{self.serial}",
            auth=True,
            should_read=True,
            timeout=5.0,
        )
        if res is None or not res.body.get("body/US"):
            raise DeviceNotFoundError(
                f"device {self.serial} not found on {prof.name} ({prof.main_server})"
            )
        us = res.body["body/US"]
        p2p_host, p2p_port_s = us.split(":", 1)
        p2p_port = int(p2p_port_s)

        # Device probe & info (randsalt + camera service ports)
        p2psrv_remote = UDP(p2p_host, p2p_port, debug=self.debug, profile=prof, log_fn=self.log_fn)
        try:
            info = probe_device_info(p2psrv_remote, self.serial, timeout=3.0)
        finally:
            p2psrv_remote.close()

        self.device_info = info
        if info:
            self.cam_http = int(info.get("httpport") or 0)
            self.cam_priv = int(info.get("privport") or 0)
            self.cam_rtsp = int(info.get("rtspport") or 0)
            if not self.randsalt and info.get("randsalt"):
                self.randsalt = str(info["randsalt"])

        # Phase 2: Relay dispatcher lookup
        self.log_fn(f"[{prof.name}] Phase 2: relay lookup")
        relay_host = ""
        relay_port = 0
        try:
            main_remote.request_ex("/online/relay", auth=True, should_read=False)
            r_res = main_remote.read(
                return_error=False,
                timeout=3.0 if prof.relay_agent_optional else RELAY_READ_TIMEOUT,
            )
            addr_str = r_res.body.get("body/Address", "")
            if ":" in addr_str:
                rh, rp = addr_str.split(":", 1)
                relay_host, relay_port = rh, int(rp)
        except Exception as exc:
            if not prof.relay_agent_optional:
                raise RuntimeError(f"relay lookup failed: {exc}") from exc
            self.log_fn(f"relay dispatcher lookup skipped ({exc})")

        # Phase 3: p2p-channel request
        device_remote = UDP(
            prof.main_server, prof.main_port, debug=self.debug, profile=prof, log_fn=self.log_fn
        )
        self.device_remote = device_remote

        if self.dtype > 0 and (not self.username or not self.password):
            raise ValueError("username and password required for dtype > 0")

        aid = os.urandom(8)
        fwd_port = self.specs[0].remote if self.specs else 554
        chan_req = ChannelRequest.create(
            prof=prof,
            dtype=self.dtype,
            username=self.username,
            password=self.password,
            randsalt=self.randsalt,
            aid=aid,
            bind_ip=device_remote.bind_ip,
            lport=device_remote.lport,
            fwd_port=fwd_port,
        )

        def _send_channel(retransmit: bool = False) -> None:
            if retransmit:
                chan_req.regenerate()
            device_remote.request_ex(
                f"/device/{self.serial}/p2p-channel",
                body=chan_req.body(),
                auth=True,
                should_read=False,
                cseq=chan_req.cseq,
                pcs_id=chan_req.pcs_id,
            )

        _send_channel(retransmit=False)

        early: Optional[DHResponse] = None
        if prof.channel_retransmit:
            early = self._wait_channel_early_ack(device_remote, chan_req, _send_channel)

        # Relay agent allocation
        agent_host = ""
        agent_port = 0
        agent_token = ""
        if relay_host:
            try:
                main_remote.set_remote(relay_host, relay_port)
                main_remote.request_ex("/relay/agent", auth=True, should_read=False)
                a_res = main_remote.read(
                    return_error=False,
                    timeout=3.0 if prof.relay_agent_optional else RELAY_READ_TIMEOUT,
                )
                agent_token = a_res.body.get("body/Token", "")
                ag_str = a_res.body.get("body/Agent", "")
                if ":" in ag_str:
                    ah, ap = ag_str.split(":", 1)
                    agent_host, agent_port = ah, int(ap)
            except Exception as exc:
                if not prof.relay_agent_optional:
                    raise RuntimeError(f"relay agent allocation failed: {exc}") from exc
                self.log_fn(f"relay agent unavailable ({exc})")

        agent_ok = bool(agent_host and agent_token)
        if agent_ok:
            try:
                main_remote.set_remote(agent_host, agent_port)
                main_remote.request_ex(
                    f"/relay/start/{agent_token}",
                    body="<body><Client>:0</Client></body>",
                    auth=True,
                    should_read=True,
                    timeout=3.0,
                )
            except Exception as exc:
                self.log_fn(f"relay/start warning: {exc}")

        # Phase 4: Server Nat Info from device
        if early is None:
            res = device_remote.read(return_error=True, timeout=RELAY_READ_TIMEOUT)
            while res.code < 200:
                res = device_remote.read(return_error=True, timeout=RELAY_READ_TIMEOUT)
        else:
            res = early

        if res.code >= 400:
            if res.code == 404:
                raise DeviceNotFoundError(f"device {self.serial} returned 404")
            if res.code in (401, 403):
                raise DeviceAuthError(
                    f"device authentication failed (code={res.code} {res.status})"
                )
            raise RuntimeError(f"device response: code={res.code} {res.status}")

        device_laddr = res.body.get("body/LocalAddr", "")
        device_pub = res.body.get("body/PubAddr", "")
        policy = res.body.get("body/Policy", "")
        tcp_relay_allowed = "tcprelay" in policy

        if self.dtype > 0:
            nonce_str = res.body.get("body/Nonce", "")
            if nonce_str:
                try:
                    device_laddr = get_dec(chan_req.key, int(nonce_str), device_laddr)
                except ValueError:
                    pass

        if ":" not in device_pub:
            raise RuntimeError(f"device ack missing PubAddr (LocalAddr={device_laddr!r})")
        dev_ip, dev_port_s = device_pub.split(":", 1)
        dev_port = int(dev_port_s)
        device_remote.set_remote(dev_ip, dev_port)

        # Best-effort local-channel step for DMSS / InstaOn app parity
        if prof.local_channel:
            threading.Thread(
                target=self._send_local_channel,
                args=(chan_req.key,),
                daemon=True,
            ).start()

        # Option A: Forced TCP-relay (--tcp-relay)
        if self.use_tcp:
            auth_str = (
                get_auth(self.username, chan_req.key, get_nonce(), "", self.randsalt)
                if self.dtype > 0
                else ""
            )
            try:
                thost, tport, ttok = self._request_tcprelay_channel(main_remote, auth_str)
                rport = self.specs[0].remote if self.specs else 80
                self.tou = TOUChannel.dial(
                    prof, thost, tport, ttok, remote_port=rport, debug=self.debug, log_fn=self.log_fn
                )
                self.use_tcp_path = True
                self.is_direct = False
                return
            except Exception as exc:
                self.log_fn(f"TCP relay failed ({exc}), falling back to UDP")
                self.use_tcp = False

        # Option B: Forced UDP-relay (--relay)
        if self.force_relay:
            if not agent_ok:
                raise RuntimeError("relay agent unavailable but force_relay was specified")
            auth_str = (
                get_auth(self.username, chan_req.key, get_nonce(), "", self.randsalt)
                if self.dtype > 0
                else ""
            )
            self._wait_relay_channel_ack(main_remote, agent_host, agent_port, auth_str)
            main_remote.request_ptcp(PTCP_SYNC_BODY)
            main_remote.read_ptcp(timeout=RELAY_READ_TIMEOUT)
            main_remote.request_ptcp(b"")
            self.primary = main_remote
            self.is_direct = False
            return

        # Option C: Race Direct Inverted-STUN hole-punch vs UDP Relay
        stun_ok = self._attempt_stun_punch(device_remote, aid, dev_ip, dev_port, device_laddr)
        if stun_ok:
            device_remote.request_ptcp(PTCP_SYNC_BODY)
            try:
                device_remote.read_ptcp(timeout=2.0)
            except Exception:
                pass
            self.primary = device_remote
            self.is_direct = True
            self.log_fn("Connected via direct STUN path")
            return

        # Fallback to UDP Relay
        if agent_ok:
            auth_str = (
                get_auth(self.username, chan_req.key, get_nonce(), "", self.randsalt)
                if self.dtype > 0
                else ""
            )
            try:
                self._wait_relay_channel_ack(main_remote, agent_host, agent_port, auth_str)
                main_remote.request_ptcp(PTCP_SYNC_BODY)
                main_remote.read_ptcp(timeout=RELAY_READ_TIMEOUT)
                main_remote.request_ptcp(b"")
                self.primary = main_remote
                self.is_direct = False
                self.log_fn("Connected via UDP relay path")
                return
            except Exception as exc:
                self.log_fn(f"UDP relay fallback failed: {exc}")

        # Fallback to TCP Relay if policy permits
        if tcp_relay_allowed and agent_ok:
            rport = self.specs[0].remote if self.specs else 80
            self.tou = TOUChannel.dial(
                prof,
                agent_host,
                agent_port,
                agent_token,
                remote_port=rport,
                debug=self.debug,
                log_fn=self.log_fn,
            )
            self.use_tcp_path = True
            self.is_direct = False
            self.log_fn("Connected via TCP relay fallback")
            return

        raise RuntimeError("STUN punch failed and relay path unavailable")

    def _wait_channel_early_ack(
        self,
        device_remote: UDP,
        chan_req: ChannelRequest,
        send_fn: Callable[[bool], None],
    ) -> Optional[DHResponse]:
        window = 1.8
        max_retrans = 2
        slot = window / (max_retrans + 1)
        start = time.monotonic()
        end = start + window
        sent_retrans = 0

        while True:
            now = time.monotonic()
            if now >= end:
                return None
            next_slot = start + (sent_retrans + 1) * slot
            if sent_retrans < max_retrans and now >= next_slot:
                sent_retrans += 1
                send_fn(True)
                continue
            wait_for = end - now
            if sent_retrans < max_retrans and (next_slot - now) < wait_for:
                wait_for = next_slot - now

            try:
                data = device_remote.recv(4096, timeout=max(0.05, wait_for))
            except socket.timeout:
                continue
            except Exception:
                return None

            res = parse_dh_response(data.decode("utf-8", errors="replace"))
            if res.code >= 400:
                return res
            if chan_req.pcs_id:
                if res.header("x-pcs-request-id") != chan_req.pcs_id:
                    continue
            elif res.header("CSeq") != str(chan_req.cseq):
                continue
            if res.code < 200:
                continue
            return res

    def _wait_relay_channel_ack(
        self, main_remote: UDP, agent_host: str, agent_port: int, auth_str: str
    ) -> None:
        req_path = f"/device/{self.serial}/relay-channel"
        req_body = f"<body>{auth_str}<agentAddr>{agent_host}:{agent_port}</agentAddr></body>"
        cseq = next_cseq_for(self.profile)

        intervals = [1.2, 2.4, 2.4, 2.4]
        for wait_sec in intervals:
            main_remote.set_remote(self.profile.main_server, self.profile.main_port)
            main_remote.request_ex(
                req_path, body=req_body, auth=True, should_read=False, cseq=cseq
            )
            main_remote.set_remote(agent_host, agent_port)
            try:
                res = main_remote.read(return_error=True, timeout=wait_sec)
                if res.code < 300:
                    return
            except socket.timeout:
                continue
        raise TimeoutError("relay-channel ack timed out")

    def _request_tcprelay_channel(
        self, remote: UDP, auth_str: str
    ) -> tuple[str, int, str]:
        req_path = f"/device/{self.serial}/tcprelay-channel"
        req_body = f"<body>{auth_str}</body>"
        cseq = next_cseq_for(self.profile)
        remote.request_ex(req_path, body=req_body, auth=True, should_read=False, cseq=cseq)
        res = remote.read(return_error=True, timeout=RELAY_READ_TIMEOUT)
        if res.code != 200:
            raise RuntimeError(f"tcprelay-channel returned {res.code} {res.status}")
        agent = res.body.get("body/Agent", "")
        token = res.body.get("body/Token", "")
        if ":" not in agent or not token:
            raise RuntimeError("tcprelay-channel missing Agent or Token")
        host, port_s = agent.split(":", 1)
        return host, int(port_s), token

    def _send_local_channel(self, chan_key: bytes) -> None:
        u = UDP(
            self.profile.main_server,
            self.profile.main_port,
            debug=self.debug,
            profile=self.profile,
            log_fn=self.log_fn,
        )
        try:
            body = ""
            if self.dtype > 0:
                body = f"<body>{get_auth(self.username, chan_key, get_nonce(), '', self.randsalt)}</body>"
            u.request_ex(
                f"/device/{self.serial}/local-channel",
                body=body,
                auth=True,
                should_read=False,
                verb=self.profile.verb_get,
            )
            u.read(return_error=False, timeout=2.0)
        except Exception:
            pass
        finally:
            u.close()

    def _attempt_stun_punch(
        self,
        device_remote: UDP,
        aid: bytes,
        dev_ip: str,
        dev_port: int,
        device_laddr: str,
    ) -> bool:
        inv_aid = invert_bytes(aid)
        cookie = os.urandom(4)
        trans_id = os.urandom(12)
        eaddr = invert_bytes(struct.pack("!H", dev_port) + socket.inet_aton(dev_ip))

        stun_init = (
            b"\xff\xfe\xff\xe7"
            + cookie
            + trans_id
            + b"\x7f\xd5\xff\xf7"
            + inv_aid
            + b"\xff\xfb\xff\xf7\xff\xfe"
            + eaddr
        )

        local_target: Optional[tuple[str, int]] = None
        if ":" in device_laddr:
            lip, lport_s = device_laddr.split(":", 1)
            try:
                local_target = (lip, int(lport_s))
            except ValueError:
                local_target = None

        def _send_burst() -> None:
            if local_target and local_target[1] > 0:
                device_remote.send_to(stun_init, local_target)
            device_remote.send(stun_init)
            for off in range(1, 33):
                if dev_port + off <= 65535:
                    device_remote.send_to(stun_init, (dev_ip, dev_port + off))

        _send_burst()
        deadline = time.monotonic() + 2.5
        attempts = 0
        got_stun = False

        while time.monotonic() < deadline:
            try:
                data, addr = device_remote.recv_from(4096, timeout=0.25)
            except socket.timeout:
                attempts += 1
                if attempts < 6:
                    _send_burst()
                    continue
                break
            except Exception:
                break

            if len(data) < 20:
                continue
            if data[0] == 0xFE and data[1] == 0xFE:
                device_remote.set_remote(addr[0], addr[1])
                got_stun = True
                break
            if data[0] == 0xFF and data[1] == 0xFE:
                device_remote.set_remote(addr[0], addr[1])
                resp = (
                    b"\xfe\xfe\xff\xe7"
                    + data[4:8]
                    + data[8:20]
                    + b"\x7f\xd6\xff\xf7"
                    + inv_aid
                )
                if len(data) >= 40:
                    resp += b"\xff\xfb\xff\xf7\xff\xfe" + data[34:40]
                for _ in range(3):
                    device_remote.send_to(resp, addr)
                got_stun = True
                break

        if not got_stun:
            return False

        confirm = (
            b"\xfe\xfe\xff\xf3"
            + cookie
            + trans_id
            + b"\x7f\xd6\xff\xf7"
            + inv_aid
        )
        for _ in range(5):
            device_remote.send(confirm)
        time.sleep(0.08)
        while True:
            try:
                device_remote.recv_from(4096, timeout=0.1)
            except Exception:
                break
        return True

    def start_listeners(self) -> dict[int, int]:
        """Bind local TCP listeners and launch reader/heartbeat threads."""
        def _override(default_port: int, real_port: int) -> None:
            if real_port <= 0 or real_port == default_port:
                return
            for spec in self.specs:
                if spec.remote == default_port:
                    spec.remote = real_port

        _override(80, self.cam_http)
        _override(37777, self.cam_priv)
        _override(554, self.cam_rtsp)

        for spec in self.specs:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.bind_address, spec.local))
            srv.listen(32)
            actual_local = srv.getsockname()[1]
            spec.local = actual_local
            self.bound_ports[spec.remote] = actual_local
            self.listeners.append(srv)

            t = threading.Thread(
                target=self._accept_loop,
                args=(srv, spec.remote),
                daemon=True,
            )
            t.start()
            self._threads.append(t)

        if self.use_tcp_path:
            for target in (self._tou_read_loop, self._tou_heartbeat_loop):
                t = threading.Thread(target=target, daemon=True)
                t.start()
                self._threads.append(t)
        else:
            for u in (self.device_remote, self.main_remote):
                if u is not None:
                    t = threading.Thread(target=self._ptcp_read_loop, args=(u,), daemon=True)
                    t.start()
                    self._threads.append(t)
            hb = threading.Thread(target=self._ptcp_heartbeat_loop, daemon=True)
            hb.start()
            self._threads.append(hb)

        return dict(self.bound_ports)

    def start(self) -> dict[int, int]:
        """Establish the P2P tunnel and start local TCP listeners."""
        self.establish()
        return self.start_listeners()

    def stop(self) -> None:
        """Close all listeners, active client connections, and UDP/TCP sockets."""
        self._stop_event.set()
        for srv in self.listeners:
            try:
                srv.close()
            except Exception:
                pass
        self.listeners.clear()

        with self._clients_lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for c in clients:
            c.close()

        if self.tou is not None:
            self.tou.close()
        if self.device_remote is not None:
            self.device_remote.close()
        if self.main_remote is not None:
            self.main_remote.close()

    def _accept_loop(self, srv: socket.socket, remote_port: int) -> None:
        while not self._stop_event.is_set():
            try:
                conn, _addr = srv.accept()
            except Exception:
                if self._stop_event.is_set():
                    return
                continue
            self.touch_activity()
            threading.Thread(
                target=self._handle_bind,
                args=(conn, remote_port),
                daemon=True,
            ).start()

    def _handle_bind(self, conn: socket.socket, remote_port: int) -> None:
        realm_id = struct.unpack("!I", os.urandom(4))[0]
        if self.use_tcp_path:
            if self.tou is None:
                conn.close()
                return
            self._add_client(realm_id, conn, remote_port)
            try:
                self.tou.write(tou_build_syn(realm_id, remote_port))
            except Exception:
                self._del_client(realm_id)
                conn.close()
            return

        if self.primary is None:
            conn.close()
            return

        ev = threading.Event()
        with self._bind_lock:
            self._bind_waits[realm_id] = ev

        bind_pkt = build_ptcp_bind(realm_id, remote_port)
        deadline = time.monotonic() + BIND_TIMEOUT
        while time.monotonic() < deadline and not self._stop_event.is_set():
            with self._bind_req_lock:
                if self.primary is not None:
                    self.primary.request_ptcp(bind_pkt)
            if ev.wait(timeout=0.4):
                self._add_client(realm_id, conn, remote_port)
                return

        with self._bind_lock:
            self._bind_waits.pop(realm_id, None)
        conn.close()

    def _add_client(self, realm_id: int, conn: socket.socket, remote_port: int) -> None:
        client = _ClientConn(conn=conn, remote_port=remote_port)
        with self._clients_lock:
            self._clients[realm_id] = client
        self.touch_activity()
        threading.Thread(
            target=self._client_reader,
            args=(conn, realm_id),
            daemon=True,
        ).start()

    def _del_client(self, realm_id: int) -> None:
        with self._clients_lock:
            client = self._clients.pop(realm_id, None)
        if client is not None:
            client.close()
        self.touch_activity()

    def _write_realm_data(self, realm_id: int, data: bytes) -> None:
        self.touch_activity()
        offset = 0
        n = len(data)
        while offset < n:
            chunk = data[offset : offset + DATA_SEGMENT_MAX]
            offset += len(chunk)
            if self.use_tcp_path:
                if self.tou is not None:
                    self.tou.write_data(realm_id, chunk)
            elif self.primary is not None:
                self.primary.request_ptcp(PTCPPayload(realm=realm_id, payload=chunk).to_bytes())

    def _client_reader(self, conn: socket.socket, realm_id: int) -> None:
        try:
            while not self._stop_event.is_set():
                data = conn.recv(16384)
                if not data:
                    break
                self._write_realm_data(realm_id, data)
        except Exception:
            pass
        finally:
            if not self.use_tcp_path and self.primary is not None:
                try:
                    self.primary.request_ptcp(build_ptcp_disc(realm_id))
                except Exception:
                    pass
            self._del_client(realm_id)

    def _ptcp_read_loop(self, u: UDP) -> None:
        while not self._stop_event.is_set():
            try:
                ptcp = u.read_ptcp(timeout=0.25)
            except socket.timeout:
                u.check_retransmit()
                continue
            except Exception:
                if self._stop_event.is_set():
                    return
                continue

            u.check_retransmit()
            self._route_ptcp(ptcp, u)

    def _route_ptcp(self, p: PTCP, src: UDP) -> None:
        if not p.body:
            return
        btype = p.body[0]
        if btype == PTCP_TYPE_HEARTBEAT:
            src.request_ptcp(b"")
            return
        if btype == PTCP_TYPE_STATUS and len(p.body) >= 16:
            realm = struct.unpack("!I", p.body[4:8])[0]
            state = p.body[12:16]
            src.request_ptcp(b"")
            if state == b"CONN":
                with self._bind_lock:
                    ev = self._bind_waits.pop(realm, None)
                if ev is not None:
                    ev.set()
            elif state == b"DISC":
                with self._bind_lock:
                    self._bind_waits.pop(realm, None)
                self._del_client(realm)
            return
        if btype == PTCP_TYPE_DATA:
            try:
                body = PTCPPayload.parse(p.body)
            except ValueError:
                return
            src.request_ptcp(b"")
            with self._clients_lock:
                client = self._clients.get(body.realm)
            if client is not None and body.payload:
                self.touch_activity()
                client.write_data(body.payload)
            return
        if btype in (PTCP_TYPE_PAUSE, PTCP_TYPE_PAUSE_ACK, PTCP_TYPE_RESUME, PTCP_TYPE_RESUME_ACK):
            src.request_ptcp(b"")

    def _ptcp_heartbeat_loop(self) -> None:
        while not self._stop_event.wait(timeout=3.0):
            if self.primary is not None:
                try:
                    self.primary.request_ptcp(PTCP_HEARTBEAT_BODY)
                except Exception:
                    pass
            now = time.monotonic()
            with self._clients_lock:
                items = list(self._clients.items())
            for rid, client in items:
                if client.remote_port == 554 and (now - client.last_keepalive) > 25.0:
                    ka = f"OPTIONS * RTSP/1.0\r\nCSeq: {client.cseq}\r\n\r\n".encode("ascii")
                    self._write_realm_data(rid, ka)
                    client.cseq += 1
                    client.last_keepalive = now

    def _tou_read_loop(self) -> None:
        while not self._stop_event.is_set() and self.tou is not None:
            try:
                typ, session, payload, _tot = self.tou.read_frame(timeout=5.0)
            except socket.timeout:
                continue
            except Exception:
                return
            if typ == TOU_TYPE_DATA and payload:
                with self._clients_lock:
                    client = self._clients.get(session)
                if client is not None:
                    self.touch_activity()
                    client.write_data(payload)
            elif typ == TOU_TYPE_SYN:
                try:
                    self.tou.write_ack(session, 0)
                except Exception:
                    pass

    def _tou_heartbeat_loop(self) -> None:
        while not self._stop_event.wait(timeout=6.0):
            if self.tou is not None:
                try:
                    self.tou.write_keepalive(self.tou.local_session)
                except Exception:
                    pass


def connect_tunnel(
    serial: str,
    specs: list[PortSpec],
    profiles: Optional[list[AppProfile]] = None,
    dtype: int = 1,
    username: str = "admin",
    password: str = "",
    randsalt: str = "",
    force_relay: bool = False,
    use_tcp: bool = False,
    race: bool = False,
    debug: bool = False,
    bind_address: str = "127.0.0.1",
    log_fn: Optional[Callable[[str], None]] = None,
) -> Tunnel:
    """
    Connect a Tunnel using automatic profile fallback or parallel racing (`race=True`).
    """
    prof_list = profiles if profiles else profile_fallback_order()

    if race and len(prof_list) > 1:
        winner: list[Tunnel] = []
        errors: list[Exception] = []
        lock = threading.Lock()
        done_ev = threading.Event()

        def _try_prof(p: AppProfile) -> None:
            t = Tunnel(
                serial=serial,
                specs=specs,
                profile=p,
                dtype=dtype,
                username=username,
                password=password,
                randsalt=randsalt,
                force_relay=force_relay,
                use_tcp=use_tcp,
                debug=debug,
                bind_address=bind_address,
                log_fn=log_fn,
            )
            try:
                t.establish()
                with lock:
                    if not winner:
                        winner.append(t)
                        done_ev.set()
                        return
                t.stop()
            except Exception as exc:
                t.stop()
                with lock:
                    errors.append(exc)
                    if len(errors) >= len(prof_list):
                        done_ev.set()

        for p in prof_list:
            threading.Thread(target=_try_prof, args=(p,), daemon=True).start()

        done_ev.wait(timeout=20.0)
        if winner:
            winner[0].start_listeners()
            return winner[0]
        raise RuntimeError(f"All profiles failed in race mode: {errors[-1] if errors else 'timeout'}")

    last_err: Optional[Exception] = None
    for p in prof_list:
        t = Tunnel(
            serial=serial,
            specs=specs,
            profile=p,
            dtype=dtype,
            username=username,
            password=password,
            randsalt=randsalt,
            force_relay=force_relay,
            use_tcp=use_tcp,
            debug=debug,
            bind_address=bind_address,
            log_fn=log_fn,
        )
        try:
            t.start()
            return t
        except DeviceAuthError:
            t.stop()
            raise
        except Exception as exc:
            t.stop()
            last_err = exc
    raise RuntimeError(f"All profiles failed to connect: {last_err}")
