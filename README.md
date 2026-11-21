# `ha-dh-proxy` — Home Assistant Dahua Integration

A lightweight,Home Assistant custom integration (powered by embedded [`py-dh-p2p`](../py-dh-p2p)) that proxies **Dahua**, **CP Plus (InstaOn Cloud)**, **Dolynk (DMSS)**, **Easy4IP (SmartPSS)**, and **Amcrest** P2P cameras and NVRs.

## Key Features

- **Zero External Dependencies**: Pure Python stdlib + embedded `py-dh-p2p` (`requirements: []` in `manifest.json`).
- **True Zero-Network-Load Idle Mode**: No matter how many camera entities you create (1 to 32+), **zero P2P traffic is sent** while no stream or snapshot is actively being read. The tunnel wakes on demand and automatically disconnects after the configurable **Inactivity Duration** (default `20s`).
- **Multiplexed Single Connection**: All camera channels on an NVR share one multiplexed P2P tunnel (separate PTCP realms / TOU sessions per RTSP stream or snapshot). Adding a second NVR or a different/custom cloud server profile creates an independent connection.
- **In-Memory (RAM) Snapshot Fallback Cache**: Every snapshot request fetches a fresh JPEG from the camera via HTTP Digest (`/cgi-bin/snapshot.cgi?channel=<ch>`) and stores it in RAM for the configurable **Snapshot Cache Duration** (`snapshot_cache_ttl`). If a snapshot request fails (or the camera is temporarily in error backoff), the cached RAM image is served as a fallback for up to `snapshot_cache_ttl` seconds.
- **Configurable Bind Address**:
  - `127.0.0.1` — Only Home Assistant on the local host can access the RTSP stream and HTTP snapshot URLs.
  - `0.0.0.0` — Any device on your home LAN (VLC, Frigate, Apple TV, etc.) can read the RTSP stream and snapshot URLs.
- **Interactive Setup Wizard (ConfigFlow & OptionsFlow)**:
  1. Enter NVR serial, credentials, cloud profile (`auto`, `smartpss`, `dmss`, `kvmsprolite`, `gcmob`, `-ctc`, `amcrest`, or a **custom server profile**), bind address, inactivity timeout, and snapshot cache TTL.
  2. Automatically connects to the NVR to detect the number of channels and their NVR channel titles.
  3. Pick which channels to expose as native Home Assistant `Camera` entities (each with `stream_source` RTSP URL, `async_camera_image` snapshot, and `extra_state_attributes` exposing both `rtsp_stream_url` and `snapshot_url`).

## Installation

1. Copy `custom_components/ha_dh_proxy` into your Home Assistant `config/custom_components/ha_dh_proxy` directory (or install via HACS as a custom repository).
2. Restart Home Assistant.
3. Go to **Settings → Devices & Services → Add Integration → Dahua / CP Plus P2P Proxy (`ha-dh-proxy`)**.
4. Follow the Setup Wizard to discover your NVR channels and create your cameras.

## Thanks
1. https://github.com/undervolter/dh-fwd/ (This integration wouldn't have been possible without this!)
2. Gemini - I too am getting lazy.. I guess...
