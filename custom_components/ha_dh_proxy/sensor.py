"""Diagnostic traffic sensor entities for ha-dh-proxy (received, sent, total transferred)."""
from __future__ import annotations

from typing import Callable

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import UnitOfInformation
from homeassistant.core import HomeAssistant
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DOMAIN
from .coordinator import AsyncP2PProxyCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up data transfer sensors for an NVR P2P proxy entry."""
    coordinator: AsyncP2PProxyCoordinator = hass.data[DOMAIN][entry.entry_id]
    entities: list[SensorEntity] = [
        DahuaP2PTrafficSensor(
            coordinator=coordinator,
            metric="received",
            label="Total Data Received",
            icon="mdi:download-network",
        ),
        DahuaP2PTrafficSensor(
            coordinator=coordinator,
            metric="sent",
            label="Total Data Sent",
            icon="mdi:upload-network",
        ),
        DahuaP2PTrafficSensor(
            coordinator=coordinator,
            metric="transferred",
            label="Total Data Transferred",
            icon="mdi:swap-vertical-bold",
        ),
    ]
    async_add_entities(entities, update_before_add=False)


class DahuaP2PTrafficSensor(SensorEntity):
    """Cumulative data transfer counter for the multiplexed P2P proxy."""

    _attr_should_poll = False
    _attr_device_class = SensorDeviceClass.DATA_SIZE
    _attr_state_class = SensorStateClass.TOTAL_INCREASING
    _attr_native_unit_of_measurement = UnitOfInformation.BYTES
    _attr_suggested_unit_of_measurement = UnitOfInformation.MEGABYTES
    _attr_suggested_display_precision = 2
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        coordinator: AsyncP2PProxyCoordinator,
        metric: str,
        label: str,
        icon: str,
    ) -> None:
        self._coordinator = coordinator
        self._metric = metric
        self._attr_name = f"NVR {coordinator.serial} {label}"
        self._attr_unique_id = f"{coordinator.serial}_total_data_{metric}"
        self._attr_icon = icon
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
    def available(self) -> bool:
        return self._coordinator.is_proxy_alive

    @property
    def native_value(self) -> int:
        if self._metric == "received":
            return self._coordinator.bytes_received
        if self._metric == "sent":
            return self._coordinator.bytes_sent
        return self._coordinator.bytes_transferred
