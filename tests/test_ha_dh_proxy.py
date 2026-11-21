"""
Async integration & unit tests for ha-dh-proxy (runs with zero external dependencies).
"""
import asyncio
import importlib.util
import sys
import types
import unittest
from pathlib import Path

# Load custom_components.ha_dh_proxy modules cleanly without requiring Home Assistant installed
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Stub package init so we can import coordinator & http_digest directly without HA packages
pkg_cc = types.ModuleType("custom_components")
pkg_cc.__path__ = [str(ROOT / "custom_components")]
sys.modules["custom_components"] = pkg_cc

pkg_ha = types.ModuleType("custom_components.ha_dh_proxy")
pkg_ha.__path__ = [str(ROOT / "custom_components" / "ha_dh_proxy")]
sys.modules["custom_components.ha_dh_proxy"] = pkg_ha

from custom_components.ha_dh_proxy.const import (  # noqa: E402
    CONF_APP_PROFILE,
    CONF_BIND_ADDRESS,
    CONF_CUSTOM_PORT,
    CONF_CUSTOM_SERVER,
    CONF_CUSTOM_WSSE_KEY,
    CONF_CUSTOM_WSSE_USER,
    CONF_HEARTBEAT_TIMEOUT,
    CONF_INACTIVITY_TIMEOUT,
    CONF_PASSWORD,
    CONF_SERIAL,
    CONF_SNAPSHOT_CACHE_TTL,
    CONF_USERNAME,
    PROFILE_CUSTOM,
)
from custom_components.ha_dh_proxy.coordinator import (  # noqa: E402
    AsyncP2PProxyCoordinator,
    ProxyDisabledError,
    ProxyUnavailableError,
    build_profiles_from_config,
)
from custom_components.ha_dh_proxy.http_digest import (  # noqa: E402
    build_digest_auth_header,
    parse_channel_titles,
)


class _FakeAsyncTunnel:
    """In-memory mock of AsyncP2PTunnel simulating a Dahua/CP Plus NVR over P2P."""

    def __init__(
        self,
        connect_counter: list[int],
        realm_counter: list[int],
        fail_channels: set[int] | None = None,
    ) -> None:
        self.connected = False
        self.active_profile = None
        self.is_direct = True
        self.use_tcp_path = False
        self.connect_counter = connect_counter
        self.realm_counter = realm_counter
        self.fail_channels = fail_channels if fail_channels is not None else set()
        self.fake_recv_age: float = 0.0
        self.heartbeats_sent: int = 0
        self._servers: list[asyncio.AbstractServer] = []

    def last_recv_age(self) -> float:
        return self.fake_recv_age

    def send_heartbeat(self) -> bool:
        if not self.connected:
            return False
        self.heartbeats_sent += 1
        return True

    async def async_connect(self) -> None:
        await asyncio.sleep(0.02)
        self.connected = True
        self.connect_counter.append(1)

    async def async_close(self) -> None:
        self.connected = False
        for srv in self._servers:
            srv.close()
        self._servers.clear()

    async def async_open_realm(
        self, remote_port: int
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        self.realm_counter.append(remote_port)

        if remote_port == 80:
            srv = await asyncio.start_server(self._fake_nvr_http, "127.0.0.1", 0)
        else:
            srv = await asyncio.start_server(self._fake_nvr_rtsp, "127.0.0.1", 0)

        self._servers.append(srv)
        port = srv.sockets[0].getsockname()[1]
        return await asyncio.open_connection("127.0.0.1", port)

    async def _fake_nvr_http(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            raw = await reader.readuntil(b"\r\n\r\n")
            text = raw.decode("iso-8859-1")
            req_line = text.split("\r\n", 1)[0]
            path = req_line.split(" ")[1]

            if "Authorization: Digest " not in text:
                resp = (
                    b"HTTP/1.1 401 Unauthorized\r\n"
                    b'WWW-Authenticate: Digest realm="Login to TESTNVR", qop="auth", nonce="123456", opaque="abcdef"\r\n'
                    b"Connection: close\r\n"
                    b"Content-Length: 0\r\n\r\n"
                )
                writer.write(resp)
                await writer.drain()
                return

            if "ChannelTitle" in path:
                body = (
                    b"table.ChannelTitle[0].Name=Front Gate\r\n"
                    b"table.ChannelTitle[1].Name=Driveway\r\n"
                    b"table.ChannelTitle[10].Name=Backyard\r\n"
                )
                ctype = b"text/plain"
            elif "snapshot.cgi" in path:
                for ch in self.fail_channels:
                    if f"={ch}" in path:
                        err_body = b"Camera offline"
                        writer.write(
                            b"HTTP/1.1 500 Internal Server Error\r\n"
                            + f"Content-Length: {len(err_body)}\r\nConnection: close\r\n\r\n".encode()
                            + err_body
                        )
                        await writer.drain()
                        return
                body = b"\xff\xd8\xff\xe0FAKE_JPEG_DATA_" + path.encode()
                ctype = b"image/jpeg"
            else:
                body = b"Not Found"
                writer.write(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
                return

            writer.write(
                b"HTTP/1.1 200 OK\r\n"
                + b"Content-Type: "
                + ctype
                + b"\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()

    @staticmethod
    async def _fake_nvr_rtsp(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            data = await reader.read(4096)
            if data:
                writer.write(b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n")
                await writer.drain()
        finally:
            writer.close()


class TestHaDhProxy(unittest.IsolatedAsyncioTestCase):
    def test_custom_server_profile(self) -> None:
        profiles = build_profiles_from_config(
            {
                CONF_APP_PROFILE: PROFILE_CUSTOM,
                CONF_CUSTOM_SERVER: "mycloud.example.com",
                CONF_CUSTOM_PORT: 8800,
                CONF_CUSTOM_WSSE_USER: "myuser",
                CONF_CUSTOM_WSSE_KEY: "mykey",
            }
        )
        self.assertEqual(len(profiles), 1)
        self.assertEqual(profiles[0].main_server, "mycloud.example.com")
        self.assertEqual(profiles[0].wsse_user, "myuser")
        self.assertEqual(profiles[0].verb_get, "NFGET")

    def test_parse_channel_titles_and_digest(self) -> None:
        titles = parse_channel_titles(
            "table.ChannelTitle[0].Name=Gate\ntable.ChannelTitle[10].Name=Porch\n"
        )
        self.assertEqual(titles, {1: "Gate", 11: "Porch"})

        hdr = build_digest_auth_header(
            "GET",
            "/cgi-bin/snapshot.cgi?channel=11",
            "admin",
            "pass123",
            {"realm": "Login to NVR", "nonce": "573277450", "qop": "auth", "opaque": "xyz"},
            cnonce="deadbeef",
        )
        self.assertTrue(hdr.startswith('Digest username="admin"'))
        self.assertIn('realm="Login to NVR"', hdr)
        self.assertIn('qop=auth', hdr)

    async def test_multiplexing_ram_cache_and_inactivity_disconnect(self) -> None:
        connects: list[int] = []
        realms: list[int] = []

        fail_channels: set[int] = set()

        coord = AsyncP2PProxyCoordinator(
            {
                CONF_SERIAL: "TESTSERIAL01",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_APP_PROFILE: "kvmsprolite",
                CONF_BIND_ADDRESS: "127.0.0.1",
                CONF_INACTIVITY_TIMEOUT: 1,
                CONF_SNAPSHOT_CACHE_TTL: 30,
            }
        )
        coord._create_tunnel = lambda: _FakeAsyncTunnel(connects, realms, fail_channels)  # type: ignore[method-assign]

        await coord.async_start()
        try:
            # 1. Idle state: zero network load (tunnel must NOT be connected)
            self.assertFalse(coord.is_tunnel_connected)
            self.assertEqual(len(connects), 0)
            self.assertGreater(coord.actual_rtsp_port, 0)
            self.assertGreater(coord.actual_http_port, 0)

            # 2. Discover NVR channels via HTTP Digest over P2P
            channels = await coord.async_discover_channels()
            self.assertEqual(channels, {1: "Front Gate", 2: "Driveway", 11: "Backyard"})
            self.assertTrue(coord.is_tunnel_connected)
            self.assertEqual(len(connects), 1)

            # 3. Fetch snapshot over HTTP snapshot server -> fetches fresh from camera & caches in RAM
            r, w = await asyncio.open_connection("127.0.0.1", coord.actual_http_port)
            w.write(b"GET /snapshot/11 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await w.drain()
            resp1 = await r.read()
            w.close()
            self.assertIn(b"200 OK", resp1)
            self.assertIn(b"\xff\xd8\xff\xe0FAKE_JPEG_DATA_/cgi-bin/snapshot.cgi?channel=11&type=1", resp1)
            realms_after_first = len(realms)

            # 4. Second snapshot when camera is healthy -> still fetches fresh from camera!
            snap2 = await coord.async_get_snapshot(11)
            self.assertTrue(snap2.startswith(b"\xff\xd8"))
            self.assertGreater(len(realms), realms_after_first)

            # 5. Concurrent RTSP proxy streams multiplexed over the SAME tunnel (still 1 connect!)
            async def _rtsp_ping() -> bytes:
                rr, rw = await asyncio.open_connection("127.0.0.1", coord.actual_rtsp_port)
                rw.write(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\n\r\n")
                await rw.drain()
                out = await rr.read(1024)
                rw.close()
                return out

            res_a, res_b = await asyncio.gather(_rtsp_ping(), _rtsp_ping())
            self.assertIn(b"RTSP/1.0 200 OK", res_a)
            self.assertIn(b"RTSP/1.0 200 OK", res_b)
            self.assertEqual(len(connects), 1)  # Strictly 1 multiplexed P2P connection!

            # 6. Simulate channel 11 failing -> falls back to in-RAM cached JPEG seamlessly!
            fail_channels.add(11)
            snap_fallback = await coord.async_get_snapshot(11)
            self.assertTrue(snap_fallback.startswith(b"\xff\xd8"))
            self.assertFalse(coord.is_channel_available(11))

            # 7. Wait for inactivity_timeout (1s) -> watchdog disconnects tunnel cleanly
            await asyncio.sleep(1.5)
            self.assertFalse(coord.is_tunnel_connected)
        finally:
            await coord.async_stop()

    async def test_heartbeat_timeout_and_proxy_death_offline(self) -> None:
        connects: list[int] = []
        realms: list[int] = []
        fake_tunnel = _FakeAsyncTunnel(connects, realms)
        state_updates: list[int] = []

        coord = AsyncP2PProxyCoordinator(
            {
                CONF_SERIAL: "TESTHB01",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_APP_PROFILE: "kvmsprolite",
                CONF_BIND_ADDRESS: "127.0.0.1",
                CONF_INACTIVITY_TIMEOUT: 30,
                CONF_HEARTBEAT_TIMEOUT: 1,
                CONF_SNAPSHOT_CACHE_TTL: 0,
            }
        )
        coord._create_tunnel = lambda: fake_tunnel  # type: ignore[method-assign]
        coord.register_state_listener(lambda: state_updates.append(1))

        await coord.async_start()
        try:
            self.assertTrue(coord.is_proxy_alive)
            self.assertTrue(coord.is_channel_available(1))

            # Wake tunnel via snapshot
            await coord.async_get_snapshot(1)
            self.assertTrue(coord.is_tunnel_connected)

            # Simulate tunnel silence exceeding heartbeat_timeout (1s)
            fake_tunnel.fake_recv_age = 2.5
            await asyncio.sleep(0.6)

            # Watchdog should have disconnected the dead tunnel and set devices offline
            self.assertFalse(coord.is_tunnel_connected)
            self.assertFalse(coord.is_channel_available(1))
            self.assertIn("Heartbeat timeout", coord.last_error)
            self.assertGreater(len(state_updates), 0)
        finally:
            await coord.async_stop()

        # After proxy stops, proxy is dead and all channels report offline
        self.assertFalse(coord.is_proxy_alive)
        self.assertFalse(coord.is_channel_available(1))

    async def test_snapshot_error_backoff_no_spam(self) -> None:
        connects: list[int] = []
        realms: list[int] = []
        fail_channels = {7}

        coord = AsyncP2PProxyCoordinator(
            {
                CONF_SERIAL: "TESTERR01",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_APP_PROFILE: "kvmsprolite",
                CONF_BIND_ADDRESS: "127.0.0.1",
                CONF_INACTIVITY_TIMEOUT: 20,
                CONF_SNAPSHOT_CACHE_TTL: 0,
                "error_backoff_seconds": 30,
            }
        )
        coord._create_tunnel = lambda: _FakeAsyncTunnel(connects, realms, fail_channels)  # type: ignore[method-assign]

        await coord.async_start()
        try:
            # Channel 7 returns HTTP 500 -> should mark channel 7 offline & enter backoff
            with self.assertRaises(ProxyUnavailableError):
                await coord.async_get_snapshot(7)
            self.assertFalse(coord.is_channel_available(7))
            # Healthy channel 1 remains available!
            self.assertTrue(coord.is_channel_available(1))

            realms_after_fail = len(realms)
            # Subsequent HTTP /snapshot/7 requests during backoff must return 503 with 0 new realms!
            r, w = await asyncio.open_connection("127.0.0.1", coord.actual_http_port)
            w.write(b"GET /snapshot/7 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await w.drain()
            resp = await r.read()
            w.close()
            self.assertIn(b"503 Service Unavailable", resp)
            self.assertEqual(len(realms), realms_after_fail)
        finally:
            await coord.async_stop()

    async def test_disable_channel_and_disable_proxy(self) -> None:
        connects: list[int] = []
        realms: list[int] = []

        coord = AsyncP2PProxyCoordinator(
            {
                CONF_SERIAL: "TESTDIS01",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_APP_PROFILE: "kvmsprolite",
                CONF_BIND_ADDRESS: "127.0.0.1",
                CONF_INACTIVITY_TIMEOUT: 20,
                CONF_SNAPSHOT_CACHE_TTL: 30,
            }
        )
        coord._create_tunnel = lambda: _FakeAsyncTunnel(connects, realms)  # type: ignore[method-assign]

        await coord.async_start()
        try:
            # Disable channel 11 -> snapshot and RTSP for ch 11 rejected with 0 tunnel connections
            await coord.async_set_channel_enabled(11, False)
            self.assertFalse(coord.is_channel_available(11))
            self.assertTrue(coord.is_channel_available(1))

            with self.assertRaises(ProxyDisabledError):
                await coord.async_get_snapshot(11)

            rr, rw = await asyncio.open_connection("127.0.0.1", coord.actual_rtsp_port)
            rw.write(b"OPTIONS rtsp://127.0.0.1/cam/realmonitor?channel=11&subtype=1 RTSP/1.0\r\nCSeq: 1\r\n\r\n")
            await rw.drain()
            rtsp_resp = await rr.read(1024)
            rw.close()
            self.assertIn(b"503 Service Unavailable", rtsp_resp)
            self.assertEqual(len(connects), 0)  # Zero network load!

            # Channel 1 still works normally
            snap1 = await coord.async_get_snapshot(1)
            self.assertTrue(snap1.startswith(b"\xff\xd8"))
            self.assertTrue(coord.is_tunnel_connected)

            # Disabling master proxy immediately disconnects tunnel and sets all devices offline
            await coord.async_set_proxy_enabled(False)
            self.assertFalse(coord.is_tunnel_connected)
            self.assertFalse(coord.is_channel_available(1))
            with self.assertRaises(ProxyDisabledError):
                await coord.async_get_snapshot(1)
        finally:
            await coord.async_stop()

    async def test_optional_subtype_override_on_snapshot_and_rtsp(self) -> None:
        connects: list[int] = []
        realms: list[int] = []
        coord = AsyncP2PProxyCoordinator(
            {
                CONF_SERIAL: "TESTSUB01",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "secret",
                CONF_APP_PROFILE: "kvmsprolite",
                CONF_BIND_ADDRESS: "127.0.0.1",
                "default_subtype": 1,
            }
        )
        coord._create_tunnel = lambda: _FakeAsyncTunnel(connects, realms)  # type: ignore[method-assign]

        # RTSP rewriting: injects configured subtype=1 when missing, preserves override subtype=0
        req_no_sub = b"OPTIONS rtsp://127.0.0.1:8554/cam/realmonitor?channel=11 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        rewritten = coord._rewrite_rtsp_chunk(req_no_sub)
        self.assertIn(b"/cam/realmonitor?channel=11&subtype=1 RTSP/1.0", rewritten)

        req_with_sub = b"OPTIONS rtsp://127.0.0.1:8554/cam/realmonitor?channel=11&subtype=0 RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        preserved = coord._rewrite_rtsp_chunk(req_with_sub)
        self.assertEqual(preserved, req_with_sub)

        await coord.async_start()
        try:
            # Snapshot without subtype uses configured default (type=1)
            r1, w1 = await asyncio.open_connection("127.0.0.1", coord.actual_http_port)
            w1.write(b"GET /snapshot/11 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await w1.drain()
            resp_default = await r1.read()
            w1.close()
            self.assertIn(b"snapshot.cgi?channel=11&type=1", resp_default)

            # Snapshot with ?subtype=0 overrides configured default (type=0)
            r2, w2 = await asyncio.open_connection("127.0.0.1", coord.actual_http_port)
            w2.write(b"GET /snapshot/11?subtype=0 HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            await w2.drain()
            resp_override = await r2.read()
            w2.close()
            self.assertIn(b"snapshot.cgi?channel=11&type=0", resp_override)
        finally:
            await coord.async_stop()


if __name__ == "__main__":
    unittest.main()
