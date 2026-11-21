"""
Lightweight pure-Python async HTTP/1.1 + Digest Authentication client
operating directly over a multiplexed P2P realm (asyncio StreamReader/StreamWriter).
Zero external dependencies.
"""
import asyncio
import hashlib
import os
import re
from typing import Awaitable, Callable, Optional

RealmOpener = Callable[[int], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


def _parse_digest_challenge(header_val: str) -> dict[str, str]:
    """Parse WWW-Authenticate: Digest realm="...", qop="auth", nonce="...", opaque="..."."""
    params: dict[str, str] = {}
    val = header_val.strip()
    if val.lower().startswith("digest "):
        val = val[7:]
    for match in re.finditer(r'([a-zA-Z0-9_-]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))', val):
        key = match.group(1).lower()
        value = match.group(2) if match.group(2) is not None else match.group(3)
        params[key] = value
    return params


def build_digest_auth_header(
    method: str,
    uri: str,
    username: str,
    password: str,
    challenge: dict[str, str],
    nc: str = "00000001",
    cnonce: Optional[str] = None,
) -> str:
    """Compute RFC 2617 HTTP Digest Authorization header (MD5 / SHA-256)."""
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop_raw = challenge.get("qop", "")
    opaque = challenge.get("opaque", "")
    algo = challenge.get("algorithm", "MD5").upper()

    hash_fn = hashlib.sha256 if "SHA-256" in algo else hashlib.md5

    def _h(s: str) -> str:
        return hash_fn(s.encode("utf-8")).hexdigest()

    ha1 = _h(f"{username}:{realm}:{password}")
    ha2 = _h(f"{method}:{uri}")

    qop_list = [q.strip().lower() for q in qop_raw.split(",") if q.strip()]
    use_qop = "auth" if "auth" in qop_list else (qop_list[0] if qop_list else "")

    if cnonce is None:
        cnonce = os.urandom(8).hex()

    if use_qop:
        response = _h(f"{ha1}:{nonce}:{nc}:{cnonce}:{use_qop}:{ha2}")
    else:
        response = _h(f"{ha1}:{nonce}:{ha2}")

    parts = [
        f'username="{username}"',
        f'realm="{realm}"',
        f'nonce="{nonce}"',
        f'uri="{uri}"',
        f'response="{response}"',
    ]
    if opaque:
        parts.append(f'opaque="{opaque}"')
    if use_qop:
        parts.append(f"qop={use_qop}")
        parts.append(f"nc={nc}")
        parts.append(f'cnonce="{cnonce}"')
    if algo != "MD5":
        parts.append(f"algorithm={algo}")

    return "Digest " + ", ".join(parts)


async def _http_get_once(
    open_realm: RealmOpener,
    path: str,
    remote_port: int = 80,
    auth_header: Optional[str] = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    reader, writer = await asyncio.wait_for(open_realm(remote_port), timeout=timeout)
    try:
        req_lines = [
            f"GET {path} HTTP/1.1",
            "Host: 127.0.0.1",
            "User-Agent: ha-dh-proxy/1.0",
            "Accept: */*",
            "Connection: close",
        ]
        if auth_header:
            req_lines.append(f"Authorization: {auth_header}")
        req_bytes = ("\r\n".join(req_lines) + "\r\n\r\n").encode("utf-8")
        writer.write(req_bytes)
        await asyncio.wait_for(writer.drain(), timeout=timeout)

        # Read response headers
        raw_head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=timeout)
        head_text = raw_head.decode("iso-8859-1", errors="replace")
        lines = head_text.split("\r\n")
        status_parts = lines[0].split(" ", 2)
        status_code = int(status_parts[1]) if len(status_parts) > 1 and status_parts[1].isdigit() else 0

        headers: dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()

        # Read response body
        body = bytearray()
        if "content-length" in headers:
            try:
                content_len = int(headers["content-length"])
            except ValueError:
                content_len = 0
            if content_len > 0:
                body.extend(await asyncio.wait_for(reader.readexactly(content_len), timeout=timeout))
        elif headers.get("transfer-encoding", "").lower() == "chunked":
            while True:
                size_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if not size_line:
                    break
                size_str = size_line.split(b";", 1)[0].strip()
                if not size_str:
                    continue
                chunk_size = int(size_str, 16)
                if chunk_size == 0:
                    await asyncio.wait_for(reader.readline(), timeout=timeout)
                    break
                body.extend(await asyncio.wait_for(reader.readexactly(chunk_size), timeout=timeout))
                await asyncio.wait_for(reader.readexactly(2), timeout=timeout)  # trailing CRLF
        else:
            while True:
                chunk = await asyncio.wait_for(reader.read(16384), timeout=timeout)
                if not chunk:
                    break
                body.extend(chunk)

        return status_code, headers, bytes(body)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def async_http_digest_get(
    open_realm: RealmOpener,
    path: str,
    username: str,
    password: str,
    remote_port: int = 80,
    timeout: float = 10.0,
) -> tuple[int, dict[str, str], bytes]:
    """
    Perform an HTTP GET with automatic RFC 2617 Digest Auth retry over a multiplexed P2P realm.
    """
    code, headers, body = await _http_get_once(
        open_realm, path, remote_port=remote_port, auth_header=None, timeout=timeout
    )
    if code == 401 and "www-authenticate" in headers:
        www_auth = headers["www-authenticate"]
        if "digest" in www_auth.lower():
            challenge = _parse_digest_challenge(www_auth)
            auth_hdr = build_digest_auth_header("GET", path, username, password, challenge)
            code, headers, body = await _http_get_once(
                open_realm, path, remote_port=remote_port, auth_header=auth_hdr, timeout=timeout
            )
    return code, headers, body


def parse_channel_titles(cgi_text: str) -> dict[int, str]:
    """
    Parse Dahua/CP Plus ChannelTitle CGI response:
        table.ChannelTitle[0].Name=Front Door
        table.ChannelTitle[1].Name=Driveway
    Returns 1-indexed {channel_number: title}.
    """
    titles: dict[int, str] = {}
    for line in cgi_text.splitlines():
        m = re.match(r"table\.ChannelTitle\[(\d+)\]\.Name=(.*)", line.strip())
        if m:
            idx = int(m.group(1)) + 1  # Dahua CGI ChannelTitle is 0-indexed; RTSP/snapshot is 1-indexed
            name = m.group(2).strip()
            titles[idx] = name or f"Channel {idx}"
    return titles


async def async_discover_nvr_channels(
    open_realm: RealmOpener,
    username: str,
    password: str,
    remote_port: int = 80,
    timeout: float = 8.0,
) -> dict[int, str]:
    """
    Query the NVR over the P2P tunnel to discover how many channels exist and their titles.
    Returns a 1-indexed dict `{channel_num: channel_name}`.
    """
    # 1. Primary method: ChannelTitle config (gives both count and user-assigned names)
    try:
        code, _hdrs, body = await async_http_digest_get(
            open_realm,
            "/cgi-bin/configManager.cgi?action=getConfig&name=ChannelTitle",
            username=username,
            password=password,
            remote_port=remote_port,
            timeout=timeout,
        )
        if code == 200 and body:
            titles = parse_channel_titles(body.decode("utf-8", errors="replace"))
            if titles:
                return titles
    except Exception:
        pass

    # 2. Fallback: devVideoInput.cgi?action=getCollect (reports number of video input channels)
    try:
        code, _hdrs, body = await async_http_digest_get(
            open_realm,
            "/cgi-bin/devVideoInput.cgi?action=getCollect",
            username=username,
            password=password,
            remote_port=remote_port,
            timeout=timeout,
        )
        if code == 200 and body:
            text = body.decode("utf-8", errors="replace")
            m = re.search(r"result=(\d+)", text)
            if m:
                count = max(1, min(64, int(m.group(1))))
                return {i: f"Channel {i}" for i in range(1, count + 1)}
    except Exception:
        pass

    # 3. Fallback: MaxRemoteInputChannels
    try:
        code, _hdrs, body = await async_http_digest_get(
            open_realm,
            "/cgi-bin/magicBox.cgi?action=getProductDefinition&name=MaxRemoteInputChannels",
            username=username,
            password=password,
            remote_port=remote_port,
            timeout=timeout,
        )
        if code == 200 and body:
            text = body.decode("utf-8", errors="replace")
            m = re.search(r"MaxRemoteInputChannels=(\d+)", text)
            if m:
                count = max(1, min(64, int(m.group(1))))
                return {i: f"Channel {i}" for i in range(1, count + 1)}
    except Exception:
        pass

    return {1: "Channel 1"}


async def async_fetch_snapshot_jpeg(
    open_realm: RealmOpener,
    channel: int,
    username: str,
    password: str,
    remote_port: int = 80,
    timeout: float = 10.0,
    subtype: Optional[int] = None,
) -> bytes:
    """
    Fetch a fresh JPEG snapshot for `channel` (1-indexed) over the multiplexed P2P tunnel
    using HTTP Digest authentication. When `subtype` (0=HD, 1=SD) is provided, passes
    `type=<subtype>` per the Dahua/CP Plus CGI spec with automatic fallback.
    """
    paths: list[str] = []
    if subtype is not None:
        paths.append(f"/cgi-bin/snapshot.cgi?channel={channel}&type={subtype}")
        paths.append(f"/cgi-bin/snapshot.cgi?channel={channel}&subtype={subtype}")
    paths.append(f"/cgi-bin/snapshot.cgi?channel={channel}")
    paths.append(f"/cgi-bin/snapshot.cgi?chn={channel}")

    for path in paths:
        code, _hdrs, body = await async_http_digest_get(
            open_realm,
            path,
            username=username,
            password=password,
            remote_port=remote_port,
            timeout=timeout,
        )
        if code == 200 and body and body[:2] == b"\xff\xd8":  # JPEG SOI marker
            return body
    raise RuntimeError(f"Failed to fetch JPEG snapshot for channel {channel}")
