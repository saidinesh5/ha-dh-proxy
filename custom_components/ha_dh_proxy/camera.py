"""Camera platform for ha-dh-proxy."""
from __future__ import annotations

import logging
from typing import Any, Callable

from homeassistant.components.camera import Camera, CameraEntityFeature
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_CAMERAS, DEFAULT_SUBTYPE, DOMAIN
from .coordinator import (
    AsyncP2PProxyCoordinator,
    ProxyDisabledError,
    ProxyUnavailableError,
)

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up one Home Assistant Camera entity per configured NVR channel."""
    coordinator: AsyncP2PProxyCoordinator = hass.data[DOMAIN][entry.entry_id]
    merged = {**entry.data, **entry.options}
    cameras_cfg: list[dict[str, Any]] = merged.get(CONF_CAMERAS) or [
        {
            "channel": 1,
            "name": f"{coordinator.serial} Channel 1",
            "subtype": DEFAULT_SUBTYPE,
        }
    ]

    entities = [
        DahuaP2PCamera(
            coordinator=coordinator,
            entry_id=entry.entry_id,
            channel=int(cam["channel"]),
            name=str(cam.get("name") or f"Channel {cam['channel']}"),
            subtype=int(cam.get("subtype", DEFAULT_SUBTYPE)),
        )
        for cam in cameras_cfg
    ]
    async_add_entities(entities, update_before_add=False)


class DahuaP2PCamera(Camera):
    """
    Multiplexed on-demand Dahua / CP Plus P2P Camera entity.

    - `should_poll = False` guarantees zero background network load regardless of
      how many camera instances exist.
    - `available` immediately flips to `False` (offline) if the proxy dies,
      heartbeat times out, the device/channel is disabled, or the camera fails.
    """

    _attr_should_poll = False
    _attr_supported_features = CameraEntityFeature.STREAM
    _attr_has_entity_name = False

    def __init__(
        self,
        coordinator: AsyncP2PProxyCoordinator,
        entry_id: str,
        channel: int,
        name: str,
        subtype: int = DEFAULT_SUBTYPE,
    ) -> None:
        super().__init__()
        self._coordinator = coordinator
        self._entry_id = entry_id
        self._channel = channel
        self._subtype = subtype
        self._attr_name = name
        self._attr_unique_id = f"{coordinator.serial}_ch{channel}"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.serial)},
            name=f"NVR {coordinator.serial}",
            manufacturer="Dahua / CP Plus (P2P)",
            model=f"Cloud P2P ({coordinator.active_profile_name})",
        )
        self._unsub: Callable[[], None] | None = None

    async def async_added_to_hass(self) -> None:
        self._unsub = self._coordinator.register_state_listener(
            self.async_write_ha_state
        )

    async def async_will_remove_from_hass(self) -> None:
        if self._unsub is not None:
            self._unsub()
            self._unsub = None

    @property
    def available(self) -> bool:
        """Offline if proxy dies, heartbeat fails, device is disabled, or channel errors."""
        return self._coordinator.is_channel_available(self._channel)

    async def stream_source(self) -> str | None:
        """Return the local multiplexed RTSP proxy URL (or None if disabled/offline)."""
        if not self._coordinator.is_channel_enabled(self._channel) or not self._coordinator.is_proxy_alive:
            return None
        return self._coordinator.get_rtsp_url(
            channel=self._channel,
            subtype=self._subtype,
            host="127.0.0.1",
        )

    async def async_camera_image(
        self, width: int | None = None, height: int | None = None
    ) -> bytes | None:
        """
        Return the in-RAM cached JPEG snapshot if fresh, or fetch a new snapshot
        on demand. Quietly returns None (without error spam) when disabled/offline.
        """
        if not self._coordinator.is_channel_enabled(self._channel) or not self._coordinator.is_proxy_alive:
            return None
        try:
            return await self._coordinator.async_get_snapshot(
                self._channel, subtype=self._subtype
            )
        except (ProxyDisabledError, ProxyUnavailableError):
            # Already logged once on transition to offline by the coordinator
            return None
        except Exception as exc:
            _LOGGER.debug(
                "ha-dh-proxy [%s] channel %d snapshot failed: %s",
                self._coordinator.serial,
                self._channel,
                exc,
            )
            return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        """Expose configured stream & snapshot URLs, health, and disable state."""
        return {
            "serial": self._coordinator.serial,
            "channel": self._channel,
            "subtype": self._subtype,
            "enabled": self._coordinator.is_channel_enabled(self._channel),
            "rtsp_stream_url": self._coordinator.get_rtsp_url(
                self._channel, self._subtype
            ),
            "snapshot_url": self._coordinator.get_snapshot_url(
                self._channel, self._subtype
            ),
            "ha_snapshot_url": f"/api/ha_dh_proxy/snapshot/{self._entry_id}/{self._channel}?subtype={self._subtype}",
            "bind_address": self._coordinator.bind_address,
            "profile": self._coordinator.active_profile_name,
            "proxy_alive": self._coordinator.is_proxy_alive,
            "tunnel_connected": self._coordinator.is_tunnel_connected,
            "active_streams": self._coordinator.active_streams,
            "inactivity_timeout": self._coordinator.inactivity_timeout,
            "heartbeat_timeout": self._coordinator.heartbeat_timeout,
            "snapshot_cache_ttl": self._coordinator.snapshot_cache_ttl,
            "last_error": self._coordinator.get_channel_error(self._channel),
        }
