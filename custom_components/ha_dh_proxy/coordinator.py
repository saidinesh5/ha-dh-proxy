"""
Async P2P Proxy Coordinator for ha-dh-proxy.

Manages:
  - A single multiplexed P2P tunnel shared across all cameras on an NVR/profile.
  - Zero-network-load idle state: tunnel only connects when an RTSP stream or
    snapshot is actively requested, and disconnects after `inactivity_timeout`.
  - Active tunnel heartbeat monitoring (`heartbeat_timeout`): if the tunnel or
    proxy dies, devices are immediately marked offline (`available = False`).
  - Graceful error backoff & log throttling so a downed camera/NVR never spams
    errors or floods the cloud.
  - Per-camera and master NVR proxy enable/disable support.
  - Local asyncio RTSP proxy server (bound to 127.0.0.1 or 0.0.0.0).
  - Local asyncio HTTP snapshot server + in-RAM per-channel JPEG cache with
    configurable `snapshot_cache_ttl`.
"""
import asyncio
import logging
import re
import socket
import time
from typing import Any, Callable, Optional
from urllib.parse import quote

from .const import (
    BIND_ALL,
    BIND_LOCALHOST,
    CONF_APP_PROFILE,
    CONF_AUTH_TYPE,
    CONF_BIND_ADDRESS,
    CONF_CAMERAS,
    CONF_CUSTOM_MODERN_DIALECT,
    CONF_CUSTOM_PORT,
    CONF_CUSTOM_SERVER,
    CONF_CUSTOM_TO_U_TYPE,
    CONF_CUSTOM_WSSE_KEY,
    CONF_CUSTOM_WSSE_USER,
    CONF_DEBUG,
    CONF_DEFAULT_SUBTYPE,
    CONF_DISABLED_CHANNELS,
    CONF_HEARTBEAT_TIMEOUT,
    CONF_HTTP_PORT,
    CONF_INACTIVITY_TIMEOUT,
    CONF_PASSWORD,
    CONF_PROXY_ENABLED,
    CONF_RACE,
    CONF_RANDSALT,
    CONF_RELAY_MODE,
    CONF_RTSP_PORT,
    CONF_SERIAL,
    CONF_SNAPSHOT_CACHE_TTL,
    CONF_USERNAME,
    DEFAULT_APP_PROFILE,
    DEFAULT_AUTH_TYPE,
    DEFAULT_BIND_ADDRESS,
    DEFAULT_ERROR_BACKOFF,
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_HTTP_PORT,
    DEFAULT_INACTIVITY_TIMEOUT,
    DEFAULT_RELAY_MODE,
    DEFAULT_RTSP_PORT,
    DEFAULT_SNAPSHOT_CACHE_TTL,
    DEFAULT_SUBTYPE,
    DEFAULT_USERNAME,
    PROFILE_AUTO,
    PROFILE_CUSTOM,
    RELAY_TCP,
    RELAY_UDP,
)
from .http_digest import async_discover_nvr_channels, async_fetch_snapshot_jpeg
from .p2p.async_tunnel import AsyncP2PTunnel
from .p2p.profile import (
    AppProfile,
    make_custom_profile,
    profile_by_name,
    profile_fallback_order,
)

_LOGGER = logging.getLogger(__name__)


class ProxyDisabledError(RuntimeError):
    """Raised when the proxy or requested camera channel is disabled."""


class ProxyUnavailableError(RuntimeError):
    """Raised when the proxy or camera is offline or in error backoff."""


def build_profiles_from_config(config: dict[str, Any]) -> list[AppProfile]:
    """Resolve the list of AppProfile(s) from a config entry dict."""
    prof_name = str(config.get(CONF_APP_PROFILE, DEFAULT_APP_PROFILE)).strip()
    if prof_name == PROFILE_CUSTOM:
        return [
            make_custom_profile(
                name="custom",
                main_server=str(config.get(CONF_CUSTOM_SERVER, "")).strip(),
                main_port=int(config.get(CONF_CUSTOM_PORT, 8800)),
                wsse_user=str(config.get(CONF_CUSTOM_WSSE_USER, "")).strip(),
                wsse_user_key=str(config.get(CONF_CUSTOM_WSSE_KEY, "")).strip(),
                modern_dialect=bool(config.get(CONF_CUSTOM_MODERN_DIALECT, True)),
                to_u_type=str(
                    config.get(CONF_CUSTOM_TO_U_TYPE, "Client/KVMSProLite_Win")
                ).strip(),
            )
        ]
    if not prof_name or prof_name == PROFILE_AUTO:
        return profile_fallback_order()
    return [profile_by_name(prof_name)]


def _detect_lan_ip() -> str:
    """Best-effort detection of host LAN IPv4 when bind_address is 0.0.0.0."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


class AsyncP2PProxyCoordinator:
    """
    Multiplexes one on-demand Dahua/CP Plus P2P tunnel across multiple Home Assistant
    Camera entities, with heartbeat liveness monitoring, offline state propagation,
    error backoff, device disable controls, and in-RAM snapshot caching.
    """

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = dict(config)
        self.serial: str = str(config.get(CONF_SERIAL, "")).strip()
        self.username: str = str(config.get(CONF_USERNAME, DEFAULT_USERNAME)).strip()
        self.password: str = str(config.get(CONF_PASSWORD, ""))
        self.auth_type: int = int(config.get(CONF_AUTH_TYPE, DEFAULT_AUTH_TYPE))
        self.randsalt: str = str(config.get(CONF_RANDSALT, "")).strip()
        self.relay_mode: str = str(config.get(CONF_RELAY_MODE, DEFAULT_RELAY_MODE))
        self.race: bool = bool(config.get(CONF_RACE, False))
        self.debug: bool = bool(config.get(CONF_DEBUG, False))

        self.bind_address: str = str(
            config.get(CONF_BIND_ADDRESS, DEFAULT_BIND_ADDRESS)
        ).strip()
        self.requested_rtsp_port: int = int(config.get(CONF_RTSP_PORT, DEFAULT_RTSP_PORT))
        self.requested_http_port: int = int(config.get(CONF_HTTP_PORT, DEFAULT_HTTP_PORT))
        self.inactivity_timeout: int = max(
            1, int(config.get(CONF_INACTIVITY_TIMEOUT, DEFAULT_INACTIVITY_TIMEOUT))
        )
        self.heartbeat_timeout: float = max(
            1.0, float(config.get(CONF_HEARTBEAT_TIMEOUT, DEFAULT_HEARTBEAT_TIMEOUT))
        )
        self.snapshot_cache_ttl: int = max(
            0, int(config.get(CONF_SNAPSHOT_CACHE_TTL, DEFAULT_SNAPSHOT_CACHE_TTL))
        )
        self.default_subtype: int = int(config.get(CONF_DEFAULT_SUBTYPE, DEFAULT_SUBTYPE))
        self._channel_subtypes: dict[int, int] = {
            int(c["channel"]): int(c.get("subtype", self.default_subtype))
            for c in (config.get(CONF_CAMERAS) or [])
            if isinstance(c, dict) and str(c.get("channel", "")).isdigit()
        }
        self.error_backoff_base: float = float(
            config.get("error_backoff_seconds", DEFAULT_ERROR_BACKOFF)
        )

        self.profiles: list[AppProfile] = build_profiles_from_config(config)

        # Enable/disable controls
        self._proxy_enabled: bool = bool(config.get(CONF_PROXY_ENABLED, True))
        raw_disabled = config.get(CONF_DISABLED_CHANNELS) or []
        self._disabled_channels: set[int] = {
            int(c) for c in raw_disabled if str(c).isdigit()
        }

        # Runtime state
        self._tunnel: Optional[AsyncP2PTunnel] = None
        self._connect_lock = asyncio.Lock()
        self._rtsp_server: Optional[asyncio.AbstractServer] = None
        self._http_server: Optional[asyncio.AbstractServer] = None
        self.actual_rtsp_port: int = 0
        self.actual_http_port: int = 0

        self._active_streams: int = 0
        self._active_fetches: int = 0
        self._last_activity: float = 0.0
        self._last_heartbeat_sent: float = 0.0

        # Cumulative traffic counters (bytes)
        self._bytes_sent: int = 0
        self._bytes_received: int = 0
        self._last_traffic_notify: float = 0.0

        # Health, offline, and error backoff state
        self._proxy_running: bool = False
        self._proxy_offline: bool = False
        self._proxy_errors: int = 0
        self._proxy_backoff_until: float = 0.0
        self._last_error: str = ""

        self._channel_offline: dict[int, bool] = {}
        self._channel_errors: dict[int, int] = {}
        self._channel_backoff_until: dict[int, float] = {}
        self._channel_last_error: dict[int, str] = {}

        # In-RAM snapshot cache: (channel, subtype) -> (jpeg_bytes, monotonic_timestamp)
        self._snapshot_cache: dict[tuple[int, int], tuple[bytes, float]] = {}
        self._channel_locks: dict[int, asyncio.Lock] = {}

        # State change listeners (HA camera & switch entities)
        self._state_listeners: set[Callable[[], None]] = set()

        self._watchdog_task: Optional[asyncio.Task] = None
        self._stopped: bool = False

    def register_state_listener(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a callback invoked whenever proxy/tunnel/channel state changes."""
        self._state_listeners.add(callback)

        def _unsub() -> None:
            self._state_listeners.discard(callback)

        return _unsub

    def _notify_listeners(self) -> None:
        for cb in list(self._state_listeners):
            try:
                cb()
            except Exception:
                pass

    @property
    def is_proxy_enabled(self) -> bool:
        return self._proxy_enabled

    def is_channel_enabled(self, channel: int) -> bool:
        return self._proxy_enabled and (channel not in self._disabled_channels)

    @property
    def is_proxy_alive(self) -> bool:
        """True if local proxy listeners are running and proxy has not died."""
        if self._stopped or not self._proxy_running:
            return False
        if self._rtsp_server is None or not self._rtsp_server.is_serving():
            return False
        if self._http_server is None or not self._http_server.is_serving():
            return False
        return True

    def is_channel_available(self, channel: int) -> bool:
        """
        Whether a Home Assistant Camera entity should show as online (`available = True`).
        Returns False if:
          - the proxy died / stopped,
          - the proxy or this channel is disabled,
          - the proxy tunnel failed/heartbeat timed out (offline),
          - this specific channel is marked offline after snapshot/stream errors.
        """
        if not self.is_proxy_alive:
            return False
        if not self.is_channel_enabled(channel):
            return False
        if self._proxy_offline:
            return False
        if self._channel_offline.get(channel, False):
            return False
        return True

    def get_channel_error(self, channel: int) -> str:
        if not self._proxy_enabled:
            return "Proxy disabled"
        if channel in self._disabled_channels:
            return f"Channel {channel} disabled"
        if not self.is_proxy_alive:
            return "Proxy offline"
        if self._proxy_offline:
            return self._last_error or "Tunnel offline"
        return self._channel_last_error.get(channel, "")

    @property
    def is_tunnel_connected(self) -> bool:
        return self._tunnel is not None and self._tunnel.connected

    @property
    def active_streams(self) -> int:
        return self._active_streams

    @property
    def bytes_sent(self) -> int:
        return self._bytes_sent

    @property
    def bytes_received(self) -> int:
        return self._bytes_received

    @property
    def bytes_transferred(self) -> int:
        return self._bytes_sent + self._bytes_received

    def _record_traffic(
        self, sent: int = 0, received: int = 0, force_notify: bool = False
    ) -> None:
        if sent > 0:
            self._bytes_sent += sent
        if received > 0:
            self._bytes_received += received
        now = time.monotonic()
        if force_notify or (now - self._last_traffic_notify) >= 2.0:
            self._last_traffic_notify = now
            self._notify_listeners()

    @property
    def last_error(self) -> str:
        return self._last_error

    @property
    def active_profile_name(self) -> str:
        if self._tunnel and self._tunnel.active_profile:
            return self._tunnel.active_profile.display_name()
        return self.config.get(CONF_APP_PROFILE, DEFAULT_APP_PROFILE)

    @property
    def advertise_host(self) -> str:
        if self.bind_address == BIND_ALL:
            return _detect_lan_ip()
        return self.bind_address or BIND_LOCALHOST

    def get_effective_subtype(self, channel: int, subtype: Optional[int] = None) -> int:
        if subtype is not None:
            return int(subtype)
        return self._channel_subtypes.get(channel, self.default_subtype)

    def get_rtsp_url(
        self, channel: int, subtype: Optional[int] = None, host: Optional[str] = None
    ) -> str:
        eff_sub = self.get_effective_subtype(channel, subtype)
        target_host = host or (
            BIND_LOCALHOST
            if self.bind_address == BIND_LOCALHOST
            else self.advertise_host
        )
        user_enc = quote(self.username, safe="")
        pass_enc = quote(self.password, safe="")
        return (
            f"rtsp://{user_enc}:{pass_enc}@{target_host}:{self.actual_rtsp_port}"
            f"/cam/realmonitor?channel={channel}&subtype={eff_sub}"
        )

    def get_snapshot_url(
        self, channel: int, subtype: Optional[int] = None, host: Optional[str] = None
    ) -> str:
        eff_sub = self.get_effective_subtype(channel, subtype)
        target_host = host or (
            BIND_LOCALHOST
            if self.bind_address == BIND_LOCALHOST
            else self.advertise_host
        )
        return f"http://{target_host}:{self.actual_http_port}/snapshot/{channel}?subtype={eff_sub}"

    def _touch_activity(self) -> None:
        self._last_activity = time.monotonic()

    async def async_set_proxy_enabled(self, enabled: bool) -> None:
        """Enable or disable the entire NVR proxy device."""
        if self._proxy_enabled == enabled:
            return
        self._proxy_enabled = enabled
        if not enabled:
            _LOGGER.info("ha-dh-proxy [%s]: proxy disabled by user", self.serial)
            self._snapshot_cache.clear()
            await self.async_disconnect()
        else:
            _LOGGER.info("ha-dh-proxy [%s]: proxy re-enabled by user", self.serial)
            self._proxy_offline = False
            self._proxy_errors = 0
            self._proxy_backoff_until = 0.0
            self._last_error = ""
        self._notify_listeners()

    async def async_set_channel_enabled(self, channel: int, enabled: bool) -> None:
        """Enable or disable an individual camera channel."""
        if enabled:
            self._disabled_channels.discard(channel)
            self._channel_offline.pop(channel, None)
            self._channel_errors.pop(channel, None)
            self._channel_backoff_until.pop(channel, None)
            self._channel_last_error.pop(channel, None)
            _LOGGER.info("ha-dh-proxy [%s]: channel %d enabled", self.serial, channel)
        else:
            self._disabled_channels.add(channel)
            for key in [k for k in self._snapshot_cache if k[0] == channel]:
                self._snapshot_cache.pop(key, None)
            _LOGGER.info("ha-dh-proxy [%s]: channel %d disabled", self.serial, channel)
        self._notify_listeners()

    async def async_start(self) -> None:
        """
        Start the local asyncio RTSP & HTTP proxy listeners and heartbeat/inactivity watchdog.
        Does NOT open any P2P cloud/network connection until a stream or snapshot is requested.
        """
        self._stopped = False

        self._rtsp_server = await asyncio.start_server(
            self._handle_rtsp_client,
            host=self.bind_address,
            port=self.requested_rtsp_port,
        )
        self.actual_rtsp_port = self._rtsp_server.sockets[0].getsockname()[1]

        self._http_server = await asyncio.start_server(
            self._handle_http_snapshot_client,
            host=self.bind_address,
            port=self.requested_http_port,
        )
        self.actual_http_port = self._http_server.sockets[0].getsockname()[1]

        self._proxy_running = True
        self._proxy_offline = False
        self._watchdog_task = asyncio.create_task(self._watchdog_loop())
        self._notify_listeners()

        _LOGGER.info(
            "ha-dh-proxy [%s] listening (idle/0 network load) on %s — RTSP :%d, HTTP snapshot :%d",
            self.serial,
            self.bind_address,
            self.actual_rtsp_port,
            self.actual_http_port,
        )

    async def async_stop(self) -> None:
        """Shut down listeners, watchdog, and any active P2P tunnel; mark all devices offline."""
        self._stopped = True
        self._proxy_running = False
        if self._watchdog_task is not None:
            self._watchdog_task.cancel()
            try:
                await self._watchdog_task
            except asyncio.CancelledError:
                pass
            self._watchdog_task = None

        for srv in (self._rtsp_server, self._http_server):
            if srv is not None:
                srv.close()
                try:
                    await srv.wait_closed()
                except Exception:
                    pass
        self._rtsp_server = None
        self._http_server = None

        await self.async_disconnect()
        self._snapshot_cache.clear()
        self._notify_listeners()

    def _create_tunnel(self) -> AsyncP2PTunnel:
        return AsyncP2PTunnel(
            serial=self.serial,
            profiles=self.profiles,
            dtype=self.auth_type,
            username=self.username,
            password=self.password,
            randsalt=self.randsalt,
            force_relay=(self.relay_mode == RELAY_UDP),
            use_tcp=(self.relay_mode == RELAY_TCP),
            race=self.race,
            debug=self.debug,
            log_fn=(lambda m: _LOGGER.debug("[%s] %s", self.serial, m))
            if self.debug
            else None,
        )

    def _mark_proxy_offline(self, reason: str) -> None:
        was_offline = self._proxy_offline
        self._proxy_offline = True
        self._proxy_errors += 1
        backoff = min(120.0, self.error_backoff_base * (2 ** min(self._proxy_errors - 1, 3)))
        self._proxy_backoff_until = time.monotonic() + backoff
        self._last_error = reason
        if not was_offline:
            _LOGGER.warning(
                "ha-dh-proxy [%s]: proxy marked offline (%s); backing off for %.0fs",
                self.serial,
                reason,
                backoff,
            )
        else:
            _LOGGER.debug("ha-dh-proxy [%s]: still offline (%s)", self.serial, reason)
        self._notify_listeners()

    def _mark_proxy_online(self) -> None:
        changed = self._proxy_offline or self._proxy_errors > 0
        self._proxy_offline = False
        self._proxy_errors = 0
        self._proxy_backoff_until = 0.0
        self._last_error = ""
        if changed:
            _LOGGER.info("ha-dh-proxy [%s]: proxy back online", self.serial)
            self._notify_listeners()

    def _mark_channel_error(self, channel: int, reason: str) -> None:
        count = self._channel_errors.get(channel, 0) + 1
        self._channel_errors[channel] = count
        self._channel_last_error[channel] = reason
        backoff = min(120.0, self.error_backoff_base * (2 ** min(count - 1, 3)))
        self._channel_backoff_until[channel] = time.monotonic() + backoff
        was_offline = self._channel_offline.get(channel, False)
        self._channel_offline[channel] = True
        if not was_offline:
            _LOGGER.warning(
                "ha-dh-proxy [%s] channel %d marked offline (%s); backing off %.0fs",
                self.serial,
                channel,
                reason,
                backoff,
            )
        else:
            _LOGGER.debug(
                "ha-dh-proxy [%s] channel %d still offline (%s)",
                self.serial,
                channel,
                reason,
            )
        self._notify_listeners()

    def _mark_channel_online(self, channel: int) -> None:
        was_offline = self._channel_offline.pop(channel, False)
        self._channel_errors.pop(channel, None)
        self._channel_backoff_until.pop(channel, None)
        self._channel_last_error.pop(channel, None)
        if was_offline:
            _LOGGER.info("ha-dh-proxy [%s] channel %d back online", self.serial, channel)
            self._notify_listeners()

    async def async_ensure_connected(self, bypass_backoff: bool = False) -> AsyncP2PTunnel:
        """
        Connect the shared P2P tunnel on demand if not already active.
        Respects disable state and error backoff to avoid error/network spam.
        """
        if not self._proxy_enabled:
            raise ProxyDisabledError("Proxy is disabled")
        if self._stopped:
            raise ProxyUnavailableError("Proxy is stopped")

        self._touch_activity()
        if self._tunnel is not None and self._tunnel.connected:
            return self._tunnel

        if not bypass_backoff and time.monotonic() < self._proxy_backoff_until:
            raise ProxyUnavailableError(
                f"Proxy in error backoff ({self._last_error})"
            )

        async with self._connect_lock:
            if not self._proxy_enabled:
                raise ProxyDisabledError("Proxy is disabled")
            self._touch_activity()
            if self._tunnel is not None and self._tunnel.connected:
                return self._tunnel

            _LOGGER.info("ha-dh-proxy [%s]: waking P2P tunnel on demand", self.serial)
            tunnel = self._create_tunnel()
            try:
                await tunnel.async_connect()
            except Exception as exc:
                self._mark_proxy_offline(f"connect failed: {exc}")
                raise ProxyUnavailableError(str(exc)) from exc

            self._tunnel = tunnel
            self._last_heartbeat_sent = time.monotonic()
            self._touch_activity()
            self._mark_proxy_online()
            self._notify_listeners()
            _LOGGER.info(
                "ha-dh-proxy [%s]: P2P tunnel connected via %s (%s)",
                self.serial,
                self.active_profile_name,
                "direct STUN"
                if tunnel.is_direct
                else ("TCP relay" if tunnel.use_tcp_path else "UDP relay"),
            )
            return tunnel

    async def async_disconnect(self) -> None:
        """Tear down the underlying P2P tunnel cleanly."""
        async with self._connect_lock:
            if self._tunnel is not None:
                tunnel = self._tunnel
                self._tunnel = None
                await tunnel.async_close()
                self._notify_listeners()

    async def _watchdog_loop(self) -> None:
        """
        Combined watchdog running inside HA's asyncio event loop:
          1. Verifies local proxy listeners are still alive; if dead, marks all devices offline.
          2. While P2P tunnel is active: sends periodic heartbeats and checks `last_recv_age()`
             against `heartbeat_timeout`. If heartbeat times out or tunnel drops, tears down
             the dead tunnel and marks devices offline.
          3. When idle (`active_streams == 0`, `active_fetches == 0`) for `inactivity_timeout`,
             cleanly disconnects the P2P tunnel (zero network load).
        """
        check_interval = min(
            2.0,
            max(0.1, min(self.inactivity_timeout, self.heartbeat_timeout) / 4.0),
        )
        hb_interval = max(1.0, min(5.0, self.heartbeat_timeout / 4.0))

        while not self._stopped:
            await asyncio.sleep(check_interval)

            # 1. Proxy listener liveness check
            if not self.is_proxy_alive:
                if self._proxy_running:
                    self._proxy_running = False
                    self._mark_proxy_offline("Local proxy server stopped unexpectedly")
                    await self.async_disconnect()
                continue

            tunnel = self._tunnel
            if tunnel is None:
                continue

            now = time.monotonic()

            # 2. Active tunnel heartbeat liveness check
            if not tunnel.connected:
                await self.async_disconnect()
                self._mark_proxy_offline("P2P tunnel disconnected unexpectedly")
                continue

            if (now - self._last_heartbeat_sent) >= hb_interval:
                tunnel.send_heartbeat()
                self._last_heartbeat_sent = now

            if tunnel.last_recv_age() > self.heartbeat_timeout:
                age = tunnel.last_recv_age()
                await self.async_disconnect()
                self._mark_proxy_offline(
                    f"Heartbeat timeout (no P2P response for {age:.1f}s > {self.heartbeat_timeout:.0f}s)"
                )
                continue

            # 3. Inactivity teardown (zero network load when no receivers)
            if self._active_streams > 0 or self._active_fetches > 0:
                self._touch_activity()
                continue

            idle_for = now - self._last_activity
            if idle_for >= self.inactivity_timeout:
                _LOGGER.info(
                    "ha-dh-proxy [%s]: idle for %.1fs (>= %ds), disconnecting P2P tunnel",
                    self.serial,
                    idle_for,
                    self.inactivity_timeout,
                )
                await self.async_disconnect()

    def _get_valid_cached_snapshot(self, channel: int, subtype: int) -> Optional[bytes]:
        """Return cached JPEG bytes from RAM if still within `snapshot_cache_ttl`."""
        if self.snapshot_cache_ttl <= 0:
            return None
        cached = self._snapshot_cache.get((channel, subtype))
        if cached is None:
            return None
        img_bytes, cached_at = cached
        if (time.monotonic() - cached_at) < self.snapshot_cache_ttl:
            return img_bytes
        return None

    async def async_get_snapshot(
        self,
        channel: int,
        force_refresh: bool = False,
        subtype: Optional[int] = None,
    ) -> bytes:
        """
        Fetch a fresh JPEG snapshot for `channel` (1-indexed) from the camera.
        - Optional `subtype` (0=HD, 1=SD) overrides the configured default for this request.
        - Raises ProxyDisabledError if proxy or channel is disabled (0 network load).
        - On success, updates the in-RAM snapshot cache.
        - If the fetch fails (or the channel is in error backoff), falls back to the
          in-RAM cached image if its age is within `snapshot_cache_ttl`.
        """
        if not self.is_channel_enabled(channel):
            raise ProxyDisabledError(f"Channel {channel} is disabled")
        if not self.is_proxy_alive:
            raise ProxyUnavailableError("Proxy is offline")

        eff_sub = self.get_effective_subtype(channel, subtype)

        now = time.monotonic()
        if not force_refresh and now < self._channel_backoff_until.get(channel, 0.0):
            fallback = self._get_valid_cached_snapshot(channel, eff_sub)
            if fallback is not None:
                return fallback
            raise ProxyUnavailableError(
                f"Channel {channel} in error backoff ({self._channel_last_error.get(channel, 'offline')})"
            )

        lock = self._channel_locks.setdefault(channel, asyncio.Lock())
        async with lock:
            if not self.is_channel_enabled(channel):
                raise ProxyDisabledError(f"Channel {channel} is disabled")

            now = time.monotonic()
            if not force_refresh and now < self._channel_backoff_until.get(channel, 0.0):
                fallback = self._get_valid_cached_snapshot(channel, eff_sub)
                if fallback is not None:
                    return fallback
                raise ProxyUnavailableError(
                    f"Channel {channel} in error backoff"
                )

            self._active_fetches += 1
            self._touch_activity()
            try:
                tunnel = await self.async_ensure_connected(bypass_backoff=force_refresh)
                jpeg = await async_fetch_snapshot_jpeg(
                    open_realm=tunnel.async_open_realm,
                    channel=channel,
                    username=self.username,
                    password=self.password,
                    remote_port=80,
                    subtype=eff_sub,
                )
                self._snapshot_cache[(channel, eff_sub)] = (jpeg, time.monotonic())
                self._touch_activity()
                self._mark_channel_online(channel)
                self._record_traffic(received=len(jpeg), force_notify=True)
                return jpeg
            except ProxyDisabledError:
                raise
            except ProxyUnavailableError:
                if not force_refresh:
                    fallback = self._get_valid_cached_snapshot(channel, eff_sub)
                    if fallback is not None:
                        return fallback
                raise
            except Exception as exc:
                self._mark_channel_error(channel, str(exc))
                if not force_refresh:
                    fallback = self._get_valid_cached_snapshot(channel, eff_sub)
                    if fallback is not None:
                        return fallback
                raise ProxyUnavailableError(str(exc)) from exc
            finally:
                self._active_fetches = max(0, self._active_fetches - 1)
                self._touch_activity()

    async def async_discover_channels(self) -> dict[int, str]:
        """Connect temporarily to detect the NVR's channel count and titles."""
        self._active_fetches += 1
        self._touch_activity()
        try:
            tunnel = await self.async_ensure_connected(bypass_backoff=True)
            return await async_discover_nvr_channels(
                open_realm=tunnel.async_open_realm,
                username=self.username,
                password=self.password,
                remote_port=80,
            )
        finally:
            self._active_fetches = max(0, self._active_fetches - 1)
            self._touch_activity()

    def _rewrite_rtsp_chunk(self, chunk: bytes) -> bytes:
        """
        For RTSP request lines targeting `/cam/realmonitor?...`:
          - If `subtype=` is already present in the URL, keep the caller's override as-is.
          - If `subtype=` is missing, inject `&subtype=<configured_default_subtype>`.
        """
        def _repl(match: re.Match[bytes]) -> bytes:
            prefix = match.group(1)  # e.g. b"OPTIONS rtsp://.../cam/realmonitor?"
            query = match.group(2)   # e.g. b"channel=11"
            suffix = match.group(3)  # e.g. b" RTSP/1.0"
            if re.search(rb"(?:^|&)subtype=\d+", query):
                return match.group(0)
            ch_m = re.search(rb"(?:^|&)channel=(\d+)", query)
            ch = int(ch_m.group(1)) if ch_m else 1
            eff_sub = self.get_effective_subtype(ch, None)
            sep = b"&" if query else b""
            return prefix + query + sep + f"subtype={eff_sub}".encode("ascii") + suffix

        return re.sub(
            rb"((?:OPTIONS|DESCRIBE|SETUP|PLAY|PAUSE|TEARDOWN|GET_PARAMETER)\s+rtsp://[^\s?]+/cam/realmonitor\?)([^\s]*)( RTSP/)",
            _repl,
            chunk,
        )

    async def _handle_rtsp_client(
        self, client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter
    ) -> None:
        """Proxy one incoming RTSP TCP client over a multiplexed port-554 P2P realm."""
        if not self._proxy_enabled or not self.is_proxy_alive:
            try:
                client_writer.write(b"RTSP/1.0 503 Service Unavailable\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
            finally:
                client_writer.close()
            return

        # Peek initial RTSP bytes to check if the requested channel is disabled before waking P2P
        first_chunk = b""
        try:
            first_chunk = await asyncio.wait_for(client_reader.read(4096), timeout=5.0)
            if not first_chunk:
                client_writer.close()
                return
            m = re.search(rb"[?&]channel=(\d+)", first_chunk)
            if m:
                req_ch = int(m.group(1))
                if not self.is_channel_enabled(req_ch):
                    client_writer.write(b"RTSP/1.0 503 Service Unavailable\r\n\r\n")
                    await client_writer.drain()
                    client_writer.close()
                    return
            first_chunk = self._rewrite_rtsp_chunk(first_chunk)
        except Exception:
            client_writer.close()
            return

        self._active_streams += 1
        self._touch_activity()
        realm_writer: Optional[asyncio.StreamWriter] = None
        try:
            tunnel = await self.async_ensure_connected()
            realm_reader, realm_writer = await tunnel.async_open_realm(554)
            realm_writer.write(first_chunk)
            await realm_writer.drain()
            self._record_traffic(sent=len(first_chunk))

            async def _pipe(
                src: asyncio.StreamReader,
                dst: asyncio.StreamWriter,
                rewrite_rtsp: bool = False,
            ) -> None:
                try:
                    while not self._stopped and self._proxy_enabled:
                        chunk = await src.read(16384)
                        if not chunk:
                            break
                        self._touch_activity()
                        if rewrite_rtsp:
                            chunk = self._rewrite_rtsp_chunk(chunk)
                            self._record_traffic(sent=len(chunk))
                        else:
                            self._record_traffic(received=len(chunk))
                        dst.write(chunk)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass

            await asyncio.gather(
                _pipe(client_reader, realm_writer, rewrite_rtsp=True),
                _pipe(realm_reader, client_writer, rewrite_rtsp=False),
                return_exceptions=True,
            )
            self._record_traffic(force_notify=True)
        except (ProxyDisabledError, ProxyUnavailableError) as exc:
            _LOGGER.debug("ha-dh-proxy [%s] RTSP rejected: %s", self.serial, exc)
            try:
                client_writer.write(b"RTSP/1.0 503 Service Unavailable\r\n\r\n")
                await client_writer.drain()
            except Exception:
                pass
        except Exception as exc:
            _LOGGER.warning("ha-dh-proxy [%s] RTSP proxy error: %s", self.serial, exc)
        finally:
            self._active_streams = max(0, self._active_streams - 1)
            self._touch_activity()
            for w in (realm_writer, client_writer):
                if w is not None:
                    try:
                        w.close()
                    except Exception:
                        pass

    async def _handle_http_snapshot_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """
        Lightweight built-in HTTP/1.1 snapshot server on `bind_address:actual_http_port`:
          GET /snapshot/<channel>
          GET /snapshot?channel=<channel>
          GET /health
        """
        try:
            raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=5.0)
            req_line = raw_head.decode("iso-8859-1", errors="replace").split("\r\n", 1)[0]
            parts = req_line.split(" ")
            path = parts[1] if len(parts) > 1 else "/"

            if path == "/health":
                status_str = "ok" if (self.is_proxy_alive and not self._proxy_offline) else "offline"
                code_line = b"HTTP/1.1 200 OK\r\n" if status_str == "ok" else b"HTTP/1.1 503 Service Unavailable\r\n"
                body = f'{{"status":"{status_str}","enabled":{str(self._proxy_enabled).lower()}}}'.encode()
                writer.write(
                    code_line
                    + b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )
                await writer.drain()
                return

            channel: Optional[int] = None
            m = re.match(r"^/snapshot/(\d+)", path)
            if m:
                channel = int(m.group(1))
            else:
                m2 = re.search(r"[?&](?:channel|chn)=(\d+)", path)
                if m2:
                    channel = int(m2.group(1))

            if channel is None or channel < 1:
                msg = b"Usage: GET /snapshot/<channel>"
                writer.write(
                    b"HTTP/1.1 400 Bad Request\r\n"
                    + f"Content-Length: {len(msg)}\r\nConnection: close\r\n\r\n".encode()
                    + msg
                )
                await writer.drain()
                return

            subtype_override: Optional[int] = None
            m_sub = re.search(r"[?&](?:subtype|type)=(\d+)", path)
            if m_sub:
                subtype_override = int(m_sub.group(1))

            force = "fresh=1" in path or "nocache=1" in path
            try:
                jpeg = await self.async_get_snapshot(
                    channel, force_refresh=force, subtype=subtype_override
                )
                header = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: image/jpeg\r\n"
                    b"Cache-Control: no-store\r\n"
                    + f"Content-Length: {len(jpeg)}\r\nConnection: close\r\n\r\n".encode()
                )
                writer.write(header + jpeg)
                await writer.drain()
            except (ProxyDisabledError, ProxyUnavailableError) as exc:
                err_msg = str(exc).encode("utf-8", errors="replace")
                writer.write(
                    b"HTTP/1.1 503 Service Unavailable\r\n"
                    + f"Content-Length: {len(err_msg)}\r\nConnection: close\r\n\r\n".encode()
                    + err_msg
                )
                await writer.drain()
            except Exception as exc:
                err_msg = f"Snapshot error: {exc}".encode("utf-8", errors="replace")
                writer.write(
                    b"HTTP/1.1 502 Bad Gateway\r\n"
                    + f"Content-Length: {len(err_msg)}\r\nConnection: close\r\n\r\n".encode()
                    + err_msg
                )
                await writer.drain()
        except Exception:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
