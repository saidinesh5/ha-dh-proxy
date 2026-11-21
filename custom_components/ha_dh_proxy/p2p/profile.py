"""
Application profiles for Dahua / CP Plus / Amcrest P2P clouds.
Ported from dh-fwd/core/profile.go.
"""
from dataclasses import dataclass
import datetime
import os
from typing import Callable, Optional

MAIN_SERVER = "www.easy4ipcloud.com"
MAIN_PORT = 8800
WSSE_USERNAME = "cba1b29e32cb17aa46b8ff9e73c7f40b"
WSSE_USERKEY = "996103384cdf19179e19243e959bbf8b"

DMSS_MAIN_SERVER = "p2p.dolynkcloud.com"
DMSS_WSSE_USERNAME = "793k5zdi4dd5f037sooag8yo_dolynkc"
DMSS_WSSE_USERKEY = "ef8hatgmcuk4qamgg4fxx19x33s9q1xy"

INSTAON_MAIN_SERVER = "instaonserver.com"
INSTAON_CTC_SERVER = "instaonserverctc.com"
INSTAON_PORT = 8800

KVMS_WSSE_USERNAME = "DuvCSF0EJcNIELdlJsgjXoXhh7m_kplc"
KVMS_WSSE_USERKEY = "CD3zmkztC63QH3NomRczYTB9lv7KXEuo"

KVMS_CTC_WSSE_USERNAME = "dS8dT3mS0uF4mX1fO3kA0kR5xB_cpcbc"
KVMS_CTC_WSSE_USERKEY = "fG6uM4eV9vS2dG3jU5aH7lZ7rU9dO9bK"

GCMOB_WSSE_USERNAME = "89d61b61dc9a69fdcc03e4ff3a3be2f5"
GCMOB_WSSE_USERKEY = "993c7d7c95542c684c30ff9a9b831249"

GCMOB_CTC_WSSE_USERNAME = "zH4gW1gQ6eZ1bT1sH9yP6fR2f_cbmbap"
GCMOB_CTC_WSSE_USERKEY = "dN2cQ9gV2qU0iR3uG0wM8oI9sK0hT9mQ"

AMCREST_MAIN_SERVER = "p2p.amcrestview.com"
AMCREST_WSSE_USERNAME = "default\\1ee97e027b2140a19b08606dcede9b9e"
AMCREST_WSSE_USERKEY = "da16f30fd0af413d97921ce0d24e165c"

_server_time_offset_sec: int = 0


def get_server_time_offset() -> int:
    return _server_time_offset_sec


def set_server_time_offset(offset_sec: int) -> None:
    global _server_time_offset_sec
    _server_time_offset_sec = int(offset_sec)


def now_adjusted() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(
        seconds=_server_time_offset_sec
    )


def created_utc_z() -> str:
    return now_adjusted().strftime("%Y-%m-%dT%H:%M:%SZ")


def created_local_offset() -> str:
    local_dt = now_adjusted().astimezone().replace(microsecond=0)
    return local_dt.isoformat()


def random_hex(n_bytes: int) -> str:
    return os.urandom(n_bytes).hex()


@dataclass(frozen=True)
class AppProfile:
    name: str
    main_server: str
    main_port: int
    wsse_user: str
    wsse_user_key: str
    verb_get: str = "DHGET"
    verb_post: str = "DHPOST"
    created_now: Callable[[], str] = created_utc_z
    to_u_type: str = ""
    version: str = ""
    sversion: str = ""
    app_header_order: bool = False
    random_cseq: bool = False
    pcs_request_id: bool = False
    extended_body: bool = False
    channel_retransmit: bool = True
    local_channel: bool = False
    auto_salt: bool = False
    no_relay_auth: bool = False
    relay_agent_optional: bool = False
    warmup_path: str = "/probe/p2psrv"
    warmup_auth: bool = True

    def display_name(self) -> str:
        mapping = {
            "smartpss": "SmartPSS",
            "dmss": "DMSS",
            "kvmsprolite": "KVMS Pro Lite",
            "kvmsprolite-ctc": "KVMS Pro Lite (CTC)",
            "gcmob": "gCMOB",
            "gcmob-ctc": "gCMOB (CTC)",
            "amcrest": "Amcrest",
        }
        return mapping.get(self.name, self.name)


SMARTPSS_PROFILE = AppProfile(
    name="smartpss",
    main_server=MAIN_SERVER,
    main_port=MAIN_PORT,
    wsse_user=WSSE_USERNAME,
    wsse_user_key=WSSE_USERKEY,
    verb_get="DHGET",
    verb_post="DHPOST",
    created_now=created_utc_z,
    warmup_path="/probe/p2psrv",
    warmup_auth=True,
    channel_retransmit=True,
)

DMSS_PROFILE = AppProfile(
    name="dmss",
    main_server=DMSS_MAIN_SERVER,
    main_port=MAIN_PORT,
    wsse_user=DMSS_WSSE_USERNAME,
    wsse_user_key=DMSS_WSSE_USERKEY,
    verb_get="NFGET",
    verb_post="NFPOST",
    created_now=created_local_offset,
    to_u_type="Client/Dmss_Android",
    version="6.7.15",
    sversion="1.1.0",
    pcs_request_id=True,
    extended_body=True,
    channel_retransmit=True,
    local_channel=True,
    auto_salt=True,
    no_relay_auth=True,
    relay_agent_optional=True,
    app_header_order=True,
    random_cseq=True,
    warmup_path="/online/stun",
    warmup_auth=False,
)

KVMS_PROFILE = AppProfile(
    name="kvmsprolite",
    main_server=INSTAON_MAIN_SERVER,
    main_port=INSTAON_PORT,
    wsse_user=KVMS_WSSE_USERNAME,
    wsse_user_key=KVMS_WSSE_USERKEY,
    verb_get="NFGET",
    verb_post="NFPOST",
    created_now=created_local_offset,
    to_u_type="Client/KVMSProLite_Win",
    version="6.7.15",
    sversion="1.1.0",
    pcs_request_id=True,
    extended_body=True,
    channel_retransmit=True,
    local_channel=True,
    auto_salt=True,
    no_relay_auth=True,
    relay_agent_optional=True,
    app_header_order=True,
    random_cseq=True,
    warmup_path="/online/stun",
    warmup_auth=False,
)

KVMS_CTC_PROFILE = AppProfile(
    name="kvmsprolite-ctc",
    main_server=INSTAON_CTC_SERVER,
    main_port=INSTAON_PORT,
    wsse_user=KVMS_CTC_WSSE_USERNAME,
    wsse_user_key=KVMS_CTC_WSSE_USERKEY,
    verb_get="NFGET",
    verb_post="NFPOST",
    created_now=created_local_offset,
    to_u_type="Client/KVMSProLite_Win",
    version="6.7.15",
    sversion="1.1.0",
    pcs_request_id=True,
    extended_body=True,
    channel_retransmit=True,
    local_channel=True,
    auto_salt=True,
    no_relay_auth=True,
    relay_agent_optional=True,
    app_header_order=True,
    random_cseq=True,
    warmup_path="/online/stun",
    warmup_auth=False,
)

GCMOB_PROFILE = AppProfile(
    name="gcmob",
    main_server=INSTAON_MAIN_SERVER,
    main_port=INSTAON_PORT,
    wsse_user=GCMOB_WSSE_USERNAME,
    wsse_user_key=GCMOB_WSSE_USERKEY,
    verb_get="NFGET",
    verb_post="NFPOST",
    created_now=created_local_offset,
    to_u_type="Client/gCMOB_Android",
    version="6.7.15",
    sversion="1.1.0",
    pcs_request_id=True,
    extended_body=True,
    channel_retransmit=True,
    local_channel=True,
    auto_salt=True,
    no_relay_auth=True,
    relay_agent_optional=True,
    app_header_order=True,
    random_cseq=True,
    warmup_path="/online/stun",
    warmup_auth=False,
)

GCMOB_CTC_PROFILE = AppProfile(
    name="gcmob-ctc",
    main_server=INSTAON_CTC_SERVER,
    main_port=INSTAON_PORT,
    wsse_user=GCMOB_CTC_WSSE_USERNAME,
    wsse_user_key=GCMOB_CTC_WSSE_USERKEY,
    verb_get="NFGET",
    verb_post="NFPOST",
    created_now=created_local_offset,
    to_u_type="Client/gCMOB_Android",
    version="6.7.15",
    sversion="1.1.0",
    pcs_request_id=True,
    extended_body=True,
    channel_retransmit=True,
    local_channel=True,
    auto_salt=True,
    no_relay_auth=True,
    relay_agent_optional=True,
    app_header_order=True,
    random_cseq=True,
    warmup_path="/online/stun",
    warmup_auth=False,
)

AMCREST_PROFILE = AppProfile(
    name="amcrest",
    main_server=AMCREST_MAIN_SERVER,
    main_port=MAIN_PORT,
    wsse_user=AMCREST_WSSE_USERNAME,
    wsse_user_key=AMCREST_WSSE_USERKEY,
    verb_get="DHGET",
    verb_post="DHPOST",
    created_now=created_utc_z,
    warmup_path="/probe/p2psrv",
    warmup_auth=True,
    channel_retransmit=True,
)


def profile_by_name(name: str) -> AppProfile:
    mapping = {
        "smartpss": SMARTPSS_PROFILE,
        "easy4ip": SMARTPSS_PROFILE,
        "dmss": DMSS_PROFILE,
        "dolynk": DMSS_PROFILE,
        "kvmsprolite": KVMS_PROFILE,
        "kvms": KVMS_PROFILE,
        "instaon": KVMS_PROFILE,
        "instaoncloud": KVMS_PROFILE,
        "kvmsprolite-ctc": KVMS_CTC_PROFILE,
        "kvms-ctc": KVMS_CTC_PROFILE,
        "instaon-ctc": KVMS_CTC_PROFILE,
        "instaoncloud-ctc": KVMS_CTC_PROFILE,
        "gcmob": GCMOB_PROFILE,
        "gcmob-ctc": GCMOB_CTC_PROFILE,
        "amcrest": AMCREST_PROFILE,
    }
    if name not in mapping:
        raise ValueError(
            f'unknown app profile "{name}" (want smartpss, dmss, kvmsprolite, gcmob, amcrest, or -ctc variants)'
        )
    return mapping[name]


def profile_fallback_order() -> list[AppProfile]:
    return [
        SMARTPSS_PROFILE,
        DMSS_PROFILE,
        KVMS_PROFILE,
        GCMOB_PROFILE,
        KVMS_CTC_PROFILE,
        GCMOB_CTC_PROFILE,
    ]


def make_custom_profile(
    name: str,
    main_server: str,
    main_port: int,
    wsse_user: str,
    wsse_user_key: str,
    modern_dialect: bool = True,
    to_u_type: str = "Client/KVMSProLite_Win",
) -> AppProfile:
    """Construct a custom server profile for any OEM Dahua P2P cloud."""
    if modern_dialect:
        return AppProfile(
            name=name or "custom",
            main_server=main_server,
            main_port=main_port,
            wsse_user=wsse_user,
            wsse_user_key=wsse_user_key,
            verb_get="NFGET",
            verb_post="NFPOST",
            created_now=created_local_offset,
            to_u_type=to_u_type,
            version="6.7.15",
            sversion="1.1.0",
            pcs_request_id=True,
            extended_body=True,
            channel_retransmit=True,
            local_channel=True,
            auto_salt=True,
            no_relay_auth=True,
            relay_agent_optional=True,
            app_header_order=True,
            random_cseq=True,
            warmup_path="/online/stun",
            warmup_auth=False,
        )
    return AppProfile(
        name=name or "custom",
        main_server=main_server,
        main_port=main_port,
        wsse_user=wsse_user,
        wsse_user_key=wsse_user_key,
        verb_get="DHGET",
        verb_post="DHPOST",
        created_now=created_utc_z,
        warmup_path="/probe/p2psrv",
        warmup_auth=True,
        channel_retransmit=True,
    )
