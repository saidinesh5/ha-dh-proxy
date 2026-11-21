"""Constants for the ha-dh-proxy Home Assistant integration."""

DOMAIN = "ha_dh_proxy"

# Device & Cloud Profile config keys
CONF_SERIAL = "serial"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_AUTH_TYPE = "auth_type"
CONF_APP_PROFILE = "app_profile"
CONF_RANDSALT = "randsalt"
CONF_RELAY_MODE = "relay_mode"
CONF_RACE = "race"
CONF_DEBUG = "debug"

# Custom server profile keys
CONF_CUSTOM_SERVER = "custom_server"
CONF_CUSTOM_PORT = "custom_port"
CONF_CUSTOM_WSSE_USER = "custom_wsse_user"
CONF_CUSTOM_WSSE_KEY = "custom_wsse_key"
CONF_CUSTOM_MODERN_DIALECT = "custom_modern_dialect"
CONF_CUSTOM_TO_U_TYPE = "custom_to_u_type"

# Proxy & Caching config keys
CONF_BIND_ADDRESS = "bind_address"
CONF_RTSP_PORT = "rtsp_port"
CONF_HTTP_PORT = "http_port"
CONF_INACTIVITY_TIMEOUT = "inactivity_timeout"
CONF_HEARTBEAT_TIMEOUT = "heartbeat_timeout"
CONF_SNAPSHOT_CACHE_TTL = "snapshot_cache_ttl"
CONF_DEFAULT_SUBTYPE = "default_subtype"
CONF_DISABLED_CHANNELS = "disabled_channels"
CONF_PROXY_ENABLED = "proxy_enabled"

# Camera channel definitions stored in config entry
# List of dicts: [{"channel": 1, "name": "Front Gate", "subtype": 1}, ...]
CONF_CAMERAS = "cameras"

# Profile choices
PROFILE_AUTO = "auto"
PROFILE_CUSTOM = "custom"
PROFILE_CHOICES = [
    PROFILE_AUTO,
    "smartpss",
    "dmss",
    "kvmsprolite",
    "kvmsprolite-ctc",
    "gcmob",
    "gcmob-ctc",
    "amcrest",
    PROFILE_CUSTOM,
]

# Relay mode choices
RELAY_AUTO = "auto"
RELAY_UDP = "udp_relay"
RELAY_TCP = "tcp_relay"
RELAY_CHOICES = [RELAY_AUTO, RELAY_UDP, RELAY_TCP]

# Bind address choices
BIND_LOCALHOST = "127.0.0.1"
BIND_ALL = "0.0.0.0"
BIND_CHOICES = [BIND_LOCALHOST, BIND_ALL]

# Defaults
DEFAULT_USERNAME = "admin"
DEFAULT_AUTH_TYPE = 1
DEFAULT_APP_PROFILE = PROFILE_AUTO
DEFAULT_RELAY_MODE = RELAY_AUTO
DEFAULT_BIND_ADDRESS = BIND_LOCALHOST
DEFAULT_RTSP_PORT = 0  # 0 = auto-assign free ephemeral port
DEFAULT_HTTP_PORT = 0  # 0 = auto-assign free ephemeral port
DEFAULT_INACTIVITY_TIMEOUT = 20  # seconds before tearing down idle P2P tunnel
DEFAULT_HEARTBEAT_TIMEOUT = 30  # seconds of tunnel silence before marking proxy offline
DEFAULT_SNAPSHOT_CACHE_TTL = 30  # seconds to hold fetched JPEG snapshot in RAM
DEFAULT_SUBTYPE = 1  # 1 = SD substream, 0 = HD mainstream
DEFAULT_ERROR_BACKOFF = 30  # seconds to back off after consecutive errors to avoid log/network spam
