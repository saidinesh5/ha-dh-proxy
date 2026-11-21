"""Multi-step Config Flow & Options Flow Wizard for ha-dh-proxy."""
from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import callback
from homeassistant.data_entry_flow import FlowResult
from homeassistant.helpers import selector

from .const import (
    BIND_CHOICES,
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
    DEFAULT_HEARTBEAT_TIMEOUT,
    DEFAULT_HTTP_PORT,
    DEFAULT_INACTIVITY_TIMEOUT,
    DEFAULT_RELAY_MODE,
    DEFAULT_RTSP_PORT,
    DEFAULT_SNAPSHOT_CACHE_TTL,
    DEFAULT_SUBTYPE,
    DEFAULT_USERNAME,
    DOMAIN,
    PROFILE_CHOICES,
    PROFILE_CUSTOM,
    RELAY_CHOICES,
)
from .coordinator import AsyncP2PProxyCoordinator
from .p2p.tunnel import DeviceAuthError

_LOGGER = logging.getLogger(__name__)


def _format_channel_names_text(channels: dict[int, str]) -> str:
    return "\n".join(f"{ch}: {name}" for ch, name in sorted(channels.items()))


def _parse_channel_names_text(text: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        ch_s, name = line.split(":", 1)
        ch_s = ch_s.strip()
        if ch_s.isdigit():
            out[int(ch_s)] = name.strip() or f"Channel {ch_s}"
    return out


class HaDhProxyConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Setup Wizard for Dahua / CP Plus P2P Proxy (ha-dh-proxy)."""

    VERSION = 1

    def __init__(self) -> None:
        self._config_data: dict[str, Any] = {}
        self._discovered_channels: dict[int, str] = {1: "Channel 1"}
        self._discovery_note: str = ""

    @staticmethod
    @callback
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> HaDhProxyOptionsFlow:
        return HaDhProxyOptionsFlow(config_entry)

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 1: NVR serial, credentials, server profile, bind address, and idle timers."""
        errors: dict[str, str] = {}

        if user_input is not None:
            serial = str(user_input[CONF_SERIAL]).strip()
            user_input[CONF_SERIAL] = serial
            self._config_data = dict(user_input)

            await self.async_set_unique_id(f"{serial}_{user_input[CONF_APP_PROFILE]}")
            self._abort_if_unique_id_configured()

            if user_input[CONF_APP_PROFILE] == PROFILE_CUSTOM:
                return await self.async_step_custom_profile()

            err = await self._probe_nvr_channels()
            if err:
                errors["base"] = err
            else:
                return await self.async_step_channels()

        schema = vol.Schema(
            {
                vol.Required(CONF_SERIAL): str,
                vol.Required(CONF_USERNAME, default=DEFAULT_USERNAME): str,
                vol.Optional(CONF_PASSWORD, default=""): selector.TextSelector(
                    selector.TextSelectorConfig(type=selector.TextSelectorType.PASSWORD)
                ),
                vol.Required(CONF_AUTH_TYPE, default=DEFAULT_AUTH_TYPE): vol.In([1, 0]),
                vol.Required(
                    CONF_APP_PROFILE, default=DEFAULT_APP_PROFILE
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=PROFILE_CHOICES,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Required(
                    CONF_RELAY_MODE, default=DEFAULT_RELAY_MODE
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=RELAY_CHOICES,
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(CONF_RACE, default=False): bool,
                vol.Required(
                    CONF_BIND_ADDRESS, default=DEFAULT_BIND_ADDRESS
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(
                                value="127.0.0.1",
                                label="127.0.0.1 (Home Assistant only)",
                            ),
                            selector.SelectOptionDict(
                                value="0.0.0.0",
                                label="0.0.0.0 (Any device on local network)",
                            ),
                        ],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(CONF_RTSP_PORT, default=DEFAULT_RTSP_PORT): vol.All(
                    int, vol.Range(min=0, max=65535)
                ),
                vol.Optional(CONF_HTTP_PORT, default=DEFAULT_HTTP_PORT): vol.All(
                    int, vol.Range(min=0, max=65535)
                ),
                vol.Required(
                    CONF_INACTIVITY_TIMEOUT, default=DEFAULT_INACTIVITY_TIMEOUT
                ): vol.All(int, vol.Range(min=5, max=3600)),
                vol.Required(
                    CONF_HEARTBEAT_TIMEOUT, default=DEFAULT_HEARTBEAT_TIMEOUT
                ): vol.All(int, vol.Range(min=5, max=300)),
                vol.Required(
                    CONF_SNAPSHOT_CACHE_TTL, default=DEFAULT_SNAPSHOT_CACHE_TTL
                ): vol.All(int, vol.Range(min=0, max=3600)),
                vol.Optional(CONF_RANDSALT, default=""): str,
                vol.Optional(CONF_DEBUG, default=False): bool,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_custom_profile(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Optional Step 1b: Define a new custom cloud server profile."""
        errors: dict[str, str] = {}
        if user_input is not None:
            self._config_data.update(user_input)
            err = await self._probe_nvr_channels()
            if err:
                errors["base"] = err
            else:
                return await self.async_step_channels()

        schema = vol.Schema(
            {
                vol.Required(CONF_CUSTOM_SERVER, default="instaonserver.com"): str,
                vol.Required(CONF_CUSTOM_PORT, default=8800): vol.All(
                    int, vol.Range(min=1, max=65535)
                ),
                vol.Required(CONF_CUSTOM_WSSE_USER): str,
                vol.Required(CONF_CUSTOM_WSSE_KEY): str,
                vol.Required(CONF_CUSTOM_MODERN_DIALECT, default=True): bool,
                vol.Optional(
                    CONF_CUSTOM_TO_U_TYPE, default="Client/KVMSProLite_Win"
                ): str,
            }
        )
        return self.async_show_form(
            step_id="custom_profile", data_schema=schema, errors=errors
        )

    async def _probe_nvr_channels(self) -> str | None:
        """
        Temporarily connect to verify credentials and detect the NVR's channel count
        and channel titles, then immediately disconnect (zero lingering network load).
        """
        coord = AsyncP2PProxyCoordinator(self._config_data)
        try:
            channels = await coord.async_discover_channels()
            self._discovered_channels = channels or {1: "Channel 1"}
            if coord._tunnel and coord._tunnel.active_profile:
                self._discovery_note = (
                    f"Connected via {coord._tunnel.active_profile.display_name()} — "
                    f"detected {len(self._discovered_channels)} channel(s)."
                )
            else:
                self._discovery_note = (
                    f"Detected {len(self._discovered_channels)} channel(s)."
                )
            return None
        except DeviceAuthError:
            return "invalid_auth"
        except Exception as exc:
            _LOGGER.warning("Channel auto-discovery failed (allowing manual selection): %s", exc)
            self._discovered_channels = {i: f"Channel {i}" for i in range(1, 17)}
            self._discovery_note = (
                f"Auto-detection fell back to manual selection ({exc}). "
                "Pick the channels you want to create below."
            )
            return None
        finally:
            await coord.async_disconnect()

    async def async_step_channels(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        """Step 2: Choose which discovered NVR channels to create as HA Cameras and customize names."""
        if user_input is not None:
            selected_raw: list[str] = user_input.get("selected_channels", [])
            selected_nums = sorted({int(c) for c in selected_raw if str(c).isdigit()})
            if not selected_nums:
                selected_nums = [1]

            custom_names = _parse_channel_names_text(user_input.get("channel_names", ""))
            subtype = int(user_input.get(CONF_DEFAULT_SUBTYPE, DEFAULT_SUBTYPE))

            cameras_list = [
                {
                    "channel": ch,
                    "name": custom_names.get(
                        ch, self._discovered_channels.get(ch, f"Channel {ch}")
                    ),
                    "subtype": subtype,
                }
                for ch in selected_nums
            ]

            final_data = dict(self._config_data)
            final_data[CONF_DEFAULT_SUBTYPE] = subtype
            final_data[CONF_CAMERAS] = cameras_list

            title = f"NVR {final_data[CONF_SERIAL]} ({final_data[CONF_APP_PROFILE]})"
            return self.async_create_entry(title=title, data=final_data)

        channel_options = [
            selector.SelectOptionDict(value=str(ch), label=f"Channel {ch}: {name}")
            for ch, name in sorted(self._discovered_channels.items())
        ]
        default_selected = [str(ch) for ch in sorted(self._discovered_channels.keys())]

        schema = vol.Schema(
            {
                vol.Required(
                    "selected_channels", default=default_selected
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=channel_options,
                        multiple=True,
                        mode=selector.SelectSelectorMode.LIST,
                    )
                ),
                vol.Required(CONF_DEFAULT_SUBTYPE, default=DEFAULT_SUBTYPE): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(
                                value="1", label="Sub-stream (SD / low bandwidth)"
                            ),
                            selector.SelectOptionDict(
                                value="0", label="Main-stream (HD / full resolution)"
                            ),
                        ],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(
                    "channel_names",
                    default=_format_channel_names_text(self._discovered_channels),
                ): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                ),
            }
        )

        return self.async_show_form(
            step_id="channels",
            data_schema=schema,
            description_placeholders={"discovery_note": self._discovery_note},
        )


class HaDhProxyOptionsFlow(config_entries.OptionsFlow):
    """Options Wizard to edit bind address, idle duration, cache TTL, and camera channels."""

    def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
        self._entry = config_entry

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> FlowResult:
        merged = {**self._entry.data, **self._entry.options}

        if user_input is not None:
            names_map = _parse_channel_names_text(user_input.pop("channel_names", ""))
            raw_disabled = user_input.pop("disabled_channels_csv", "")
            disabled_list = sorted(
                {int(x.strip()) for x in str(raw_disabled).split(",") if x.strip().isdigit()}
            )
            subtype = int(user_input.get(CONF_DEFAULT_SUBTYPE, DEFAULT_SUBTYPE))
            cameras_list = [
                {"channel": ch, "name": name, "subtype": subtype}
                for ch, name in sorted(names_map.items())
            ]
            if not cameras_list:
                cameras_list = merged.get(CONF_CAMERAS) or [
                    {"channel": 1, "name": "Channel 1", "subtype": subtype}
                ]
            user_input[CONF_CAMERAS] = cameras_list
            user_input[CONF_DEFAULT_SUBTYPE] = subtype
            user_input[CONF_DISABLED_CHANNELS] = disabled_list
            return self.async_create_entry(title="", data=user_input)

        existing_cams = {
            int(c["channel"]): str(c.get("name") or f"Channel {c['channel']}")
            for c in merged.get(CONF_CAMERAS, [{"channel": 1, "name": "Channel 1"}])
        }
        existing_disabled = ", ".join(
            str(c) for c in sorted(merged.get(CONF_DISABLED_CHANNELS) or [])
        )

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_PROXY_ENABLED,
                    default=bool(merged.get(CONF_PROXY_ENABLED, True)),
                ): bool,
                vol.Required(
                    CONF_BIND_ADDRESS,
                    default=merged.get(CONF_BIND_ADDRESS, DEFAULT_BIND_ADDRESS),
                ): vol.In(BIND_CHOICES),
                vol.Required(
                    CONF_INACTIVITY_TIMEOUT,
                    default=int(
                        merged.get(CONF_INACTIVITY_TIMEOUT, DEFAULT_INACTIVITY_TIMEOUT)
                    ),
                ): vol.All(int, vol.Range(min=5, max=3600)),
                vol.Required(
                    CONF_HEARTBEAT_TIMEOUT,
                    default=int(
                        merged.get(CONF_HEARTBEAT_TIMEOUT, DEFAULT_HEARTBEAT_TIMEOUT)
                    ),
                ): vol.All(int, vol.Range(min=5, max=300)),
                vol.Required(
                    CONF_SNAPSHOT_CACHE_TTL,
                    default=int(
                        merged.get(CONF_SNAPSHOT_CACHE_TTL, DEFAULT_SNAPSHOT_CACHE_TTL)
                    ),
                ): vol.All(int, vol.Range(min=0, max=3600)),
                vol.Required(
                    CONF_RELAY_MODE,
                    default=merged.get(CONF_RELAY_MODE, DEFAULT_RELAY_MODE),
                ): vol.In(RELAY_CHOICES),
                vol.Required(
                    CONF_DEFAULT_SUBTYPE,
                    default=str(merged.get(CONF_DEFAULT_SUBTYPE, DEFAULT_SUBTYPE)),
                ): selector.SelectSelector(
                    selector.SelectSelectorConfig(
                        options=[
                            selector.SelectOptionDict(
                                value="1", label="Sub-stream (SD / low bandwidth)"
                            ),
                            selector.SelectOptionDict(
                                value="0", label="Main-stream (HD / full resolution)"
                            ),
                        ],
                        mode=selector.SelectSelectorMode.DROPDOWN,
                    )
                ),
                vol.Optional(
                    "channel_names",
                    default=_format_channel_names_text(existing_cams),
                ): selector.TextSelector(
                    selector.TextSelectorConfig(multiline=True)
                ),
                vol.Optional(
                    "disabled_channels_csv",
                    default=existing_disabled,
                ): str,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema)
