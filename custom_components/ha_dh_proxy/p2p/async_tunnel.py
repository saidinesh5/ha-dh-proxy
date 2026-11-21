"""
Asyncio adapter for py-dh-p2p so it integrates cleanly with Home Assistant's event loop.
"""
import asyncio
import os
import socket
import struct
import threading
import time
from typing import Callable, Optional

from .profile import AppProfile, profile_fallback_order
from .ptcp import PTCP_HEARTBEAT_BODY, build_ptcp_bind, build_ptcp_disc
from .tou import tou_build_syn
from .tunnel import (
    BIND_TIMEOUT,
    DeviceAuthError,
    PortSpec,
    Tunnel,
    query_device_info,
)


class AsyncP2PTunnel:
    """
    Wraps a synchronous `Tunnel` (running its UDP/PTCP read loop in daemon threads)
    and exposes non-blocking `asyncio` methods for Home Assistant's event loop:
      - `await tunnel.async_connect()`
      - `reader, writer = await tunnel.async_open_realm(remote_port)`
      - `await tunnel.async_close()`
    """

    def __init__(
        self,
        serial: str,
        profiles: Optional[list[AppProfile]] = None,
        dtype: int = 1,
        username: str = "admin",
        password: str = "",
        randsalt: str = "",
        force_relay: bool = False,
        use_tcp: bool = False,
        race: bool = False,
        debug: bool = False,
        log_fn: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.serial = serial
        self.profiles = profiles or profile_fallback_order()
        self.dtype = dtype
        self.username = username
        self.password = password
        self.randsalt = randsalt
        self.force_relay = force_relay
        self.use_tcp = use_tcp
        self.race = race
        self.debug = debug
        self.log_fn = log_fn
        self._tunnel: Optional[Tunnel] = None

    @property
    def connected(self) -> bool:
        return self._tunnel is not None and self._tunnel.is_running()

    @property
    def active_profile(self) -> Optional[AppProfile]:
        return self._tunnel.profile if self._tunnel else None

    @property
    def is_direct(self) -> bool:
        return self._tunnel.is_direct if self._tunnel else False

    @property
    def use_tcp_path(self) -> bool:
        return self._tunnel.use_tcp_path if self._tunnel else False

    @property
    def device_info(self) -> dict:
        return self._tunnel.device_info if self._tunnel else {}

    def last_recv_age(self) -> float:
        """Seconds elapsed since the last PTCP/TOU packet was received on the active transport."""
        if self._tunnel is None:
            return float("inf")
        now = time.monotonic()
        if self._tunnel.use_tcp_path and self._tunnel.tou is not None:
            return max(0.0, now - self._tunnel.tou.last_recv)
        if self._tunnel.primary is not None:
            return max(0.0, now - self._tunnel.primary.last_recv)
        return float("inf")

    def send_heartbeat(self) -> bool:
        """Send one PTCP/TOU heartbeat frame over the active transport."""
        if not self.connected or self._tunnel is None:
            return False
        try:
            if self._tunnel.use_tcp_path and self._tunnel.tou is not None:
                self._tunnel.tou.write_keepalive(self._tunnel.tou.local_session)
                return True
            if self._tunnel.primary is not None:
                self._tunnel.primary.request_ptcp(PTCP_HEARTBEAT_BODY)
                return True
        except Exception:
            return False
        return False

    def resolve_remote_port(self, requested_port: int) -> int:
        if self._tunnel is None:
            return requested_port
        if requested_port == 80 and self._tunnel.cam_http > 0:
            return self._tunnel.cam_http
        if requested_port == 554 and self._tunnel.cam_rtsp > 0:
            return self._tunnel.cam_rtsp
        if requested_port == 37777 and self._tunnel.cam_priv > 0:
            return self._tunnel.cam_priv
        return requested_port

    async def async_connect(self) -> None:
        """Establish the P2P tunnel without blocking the asyncio event loop."""
        loop = asyncio.get_running_loop()
        tunnel = await loop.run_in_executor(None, self._connect_sync)
        self._tunnel = tunnel

    def _connect_sync(self) -> Tunnel:
        prof_list = self.profiles
        if self.race and len(prof_list) > 1:
            winner: list[Tunnel] = []
            errors: list[Exception] = []
            lock = threading.Lock()
            done_ev = threading.Event()

            def _try_prof(p: AppProfile) -> None:
                t = Tunnel(
                    serial=self.serial,
                    specs=[],
                    profile=p,
                    dtype=self.dtype,
                    username=self.username,
                    password=self.password,
                    randsalt=self.randsalt,
                    force_relay=self.force_relay,
                    use_tcp=self.use_tcp,
                    debug=self.debug,
                    log_fn=self.log_fn,
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
                t = winner[0]
                t.start_listeners()
                return t
            raise RuntimeError(
                f"All profiles failed in race mode: {errors[-1] if errors else 'timeout'}"
            )

        last_err: Optional[Exception] = None
        for p in prof_list:
            t = Tunnel(
                serial=self.serial,
                specs=[],
                profile=p,
                dtype=self.dtype,
                username=self.username,
                password=self.password,
                randsalt=self.randsalt,
                force_relay=self.force_relay,
                use_tcp=self.use_tcp,
                debug=self.debug,
                log_fn=self.log_fn,
            )
            try:
                t.establish()
                t.start_listeners()
                return t
            except DeviceAuthError:
                t.stop()
                raise
            except Exception as exc:
                t.stop()
                last_err = exc
        raise RuntimeError(f"All profiles failed to connect: {last_err}")

    async def async_open_realm(
        self, remote_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Open a multiplexed PTCP realm (or TOU session) to `remote_port` on the device
        and return an asyncio (StreamReader, StreamWriter) pair backed by an OS socketpair.
        """
        if not self.connected or self._tunnel is None:
            raise ConnectionError("P2P tunnel is not connected")

        target_port = self.resolve_remote_port(remote_port)
        loop = asyncio.get_running_loop()

        # Bind the realm on a worker thread so waiting for 0x12 CONN never blocks HA's loop
        app_sock = await loop.run_in_executor(
            None, self._open_realm_socketpair_sync, self._tunnel, target_port
        )
        return await asyncio.open_connection(sock=app_sock)

    @staticmethod
    def _open_realm_socketpair_sync(tunnel: Tunnel, remote_port: int) -> socket.socket:
        app_sock, tunnel_sock = socket.socketpair()
        realm_id = struct.unpack("!I", os.urandom(4))[0]

        if tunnel.use_tcp_path:
            if tunnel.tou is None:
                app_sock.close()
                tunnel_sock.close()
                raise ConnectionError("TOU TCP relay channel unavailable")
            tunnel._add_client(realm_id, tunnel_sock, remote_port)
            try:
                tunnel.tou.write(tou_build_syn(realm_id, remote_port))
            except Exception:
                tunnel._del_client(realm_id)
                app_sock.close()
                raise
            return app_sock

        if tunnel.primary is None:
            app_sock.close()
            tunnel_sock.close()
            raise ConnectionError("PTCP primary socket unavailable")

        ev = threading.Event()
        with tunnel._bind_lock:
            tunnel._bind_waits[realm_id] = ev

        bind_pkt = build_ptcp_bind(realm_id, remote_port)
        deadline = time.monotonic() + BIND_TIMEOUT
        while time.monotonic() < deadline and not tunnel._stop_event.is_set():
            with tunnel._bind_req_lock:
                if tunnel.primary is not None:
                    tunnel.primary.request_ptcp(bind_pkt)
            if ev.wait(timeout=0.4):
                tunnel._add_client(realm_id, tunnel_sock, remote_port)
                return app_sock

        with tunnel._bind_lock:
            tunnel._bind_waits.pop(realm_id, None)
        app_sock.close()
        tunnel_sock.close()
        raise TimeoutError(f"PTCP BIND timed out for remote port {remote_port}")

    async def async_close(self) -> None:
        if self._tunnel is not None:
            t = self._tunnel
            self._tunnel = None
            loop = asyncio.get_running_loop()
            await loop.run_in_executor(None, t.stop)


async def async_query_device_info(
    serial: str,
    profile: Optional[AppProfile] = None,
    debug: bool = False,
    timeout: float = 4.0,
) -> tuple[AppProfile, str, dict]:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, query_device_info, serial, profile, debug, timeout
    )
