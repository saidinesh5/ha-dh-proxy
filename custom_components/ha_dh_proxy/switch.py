"""Switch platform for enabling/disabling the NVR P2P proxy and individual cameras."""
from __future__ import annotations

from typing import Any, Callable

from homeassistant.components.switch import SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import CONF_CAMERAS, DOMAIN
from .coordinator import AsyncP2PProxyCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Create master proxy enable switch and per-channel camera enable switches."""
    coordinator: AsyncP2PProxyCoordinator = hass.data[DOMAIN][entry.entry_id]
    merged = {**entry.data, **entry.options}
    cameras_cfg: list[dict[str, Any]] = merged.get(CONF_CAMERAS) or [
        {"channel": 1, "name": f"{coordinator.serial} Channel 1"}
    ]

    entities: list[SwitchEntity] = [
        DahuaP2PProxyEnableSwitch(coordinator=coordinator),
    ]
    for cam in cameras_cfg:
        ch = int(cam["channel"])
        cam_name = str(cam.get("name") or f"Channel {ch}")
        entities.append(
            DahuaP2PCameraEnableSwitch(
                coordinator=coordinator,
                channel=ch,
                cam_name=cam_name,
            )
        )

    async_add_entities(entities, update_before_add=False)


class DahuaP2PProxyEnableSwitch(SwitchEntity):
    """Master switch to enable or disable the entire NVR P2P proxy (0 network load when off)."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:lan-connect"

    def __init__(self, coordinator: AsyncP2PProxyCoordinator) -> None:
        self._coordinator = coordinator
        self._attr_name = f"NVR {coordinator.serial} Proxy Enabled"
        self._attr_unique_id = f"{coordinator.serial}_proxy_enabled"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.serial)},
            name=f"NVR {coordinator.serial}",
            manufacturer="Dahua / CP Plus (P2P)",
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
    def is_on(self) -> bool:
        return self._coordinator.is_proxy_enabled

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._coordinator.async_set_proxy_enabled(True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._coordinator.async_set_proxy_enabled(False)


class DahuaP2PCameraEnableSwitch(SwitchEntity):
    """Per-camera switch to enable or disable a specific NVR channel."""

    _attr_should_poll = False
    _attr_entity_category = EntityCategory.CONFIG
    _attr_icon = "mdi:cctv"

    def __init__(
        self,
        coordinator: AsyncP2PProxyCoordinator,
        channel: int,
        cam_name: str,
    ) -> None:
        self._coordinator = coordinator
        self._channel = channel
        self._attr_name = f"{cam_name} Enabled"
        self._attr_unique_id = f"{coordinator.serial}_ch{channel}_enabled"
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, coordinator.serial)},
            name=f"NVR {coordinator.serial}",
            manufacturer="Dahua / CP Plus (P2P)",
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
    def is_on(self) -> bool:
        return self._coordinator.is_channel_enabled(self._channel)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._coordinator.async_set_channel_enabled(self._channel, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._coordinator.async_set_channel_enabled(self._channel, False)
