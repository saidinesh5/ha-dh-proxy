"""Home Assistant integration entry point for ha-dh-proxy."""
from __future__ import annotations

import logging
from typing import Any

from aiohttp import web
from homeassistant.components.http import HomeAssistantView
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import Platform
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import (
    AsyncP2PProxyCoordinator,
    ProxyDisabledError,
    ProxyUnavailableError,
)

_LOGGER = logging.getLogger(__name__)
PLATFORMS: list[Platform] = [Platform.CAMERA, Platform.SWITCH, Platform.SENSOR]
_VIEW_REGISTERED_KEY = "_http_view_registered"


class HaDhProxySnapshotView(HomeAssistantView):
    """Home Assistant HTTP view: GET /api/ha_dh_proxy/snapshot/{entry_id}/{channel}."""

    url = "/api/ha_dh_proxy/snapshot/{entry_id}/{channel}"
    name = "api:ha_dh_proxy:snapshot"
    requires_auth = True

    def __init__(self, hass: HomeAssistant) -> None:
        self.hass = hass

    async def get(
        self, request: web.Request, entry_id: str, channel: str
    ) -> web.Response:
        domain_data: dict[str, Any] = self.hass.data.get(DOMAIN, {})
        coordinator: AsyncP2PProxyCoordinator | None = domain_data.get(entry_id)
        if coordinator is None:
            return web.Response(status=404, text="ha-dh-proxy entry not found")
        try:
            ch = int(channel)
            if ch < 1:
                raise ValueError
        except ValueError:
            return web.Response(status=400, text="Invalid channel number")

        subtype_override: int | None = None
        raw_sub = request.query.get("subtype") or request.query.get("type")
        if raw_sub is not None and raw_sub.isdigit():
            subtype_override = int(raw_sub)

        force = request.query.get("fresh") == "1"
        try:
            jpeg = await coordinator.async_get_snapshot(
                ch, force_refresh=force, subtype=subtype_override
            )
            return web.Response(
                body=jpeg,
                content_type="image/jpeg",
                headers={"Cache-Control": "no-store"},
            )
        except (ProxyDisabledError, ProxyUnavailableError) as exc:
            return web.Response(status=503, text=str(exc))
        except Exception as exc:
            _LOGGER.debug(
                "ha-dh-proxy snapshot view error (entry=%s ch=%d): %s",
                entry_id,
                ch,
                exc,
            )
            return web.Response(status=502, text=f"Snapshot error: {exc}")


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up ha-dh-proxy from a config entry."""
    domain_data = hass.data.setdefault(DOMAIN, {})

    if not domain_data.get(_VIEW_REGISTERED_KEY):
        hass.http.register_view(HaDhProxySnapshotView(hass))
        domain_data[_VIEW_REGISTERED_KEY] = True

    merged_config = {**entry.data, **entry.options}
    coordinator = AsyncP2PProxyCoordinator(merged_config)
    await coordinator.async_start()

    domain_data[entry.entry_id] = coordinator
    entry.async_on_unload(entry.add_update_listener(_async_update_listener))

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def _async_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload the integration when options or cameras are updated in the Wizard."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry and tear down the proxy listeners & P2P tunnel."""
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    domain_data = hass.data.get(DOMAIN, {})
    coordinator: AsyncP2PProxyCoordinator | None = domain_data.pop(entry.entry_id, None)
    if coordinator is not None:
        await coordinator.async_stop()
    return unload_ok
