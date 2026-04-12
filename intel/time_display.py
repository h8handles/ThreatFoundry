from __future__ import annotations

from dataclasses import dataclass
from zoneinfo import ZoneInfo

from django.conf import settings

TIME_DISPLAY_SESSION_KEY = "intel_time_display_option"


@dataclass(frozen=True)
class TimeDisplayOption:
    key: str
    label: str
    format_string: str
    use_utc: bool = False
    suffix: str = ""


TIME_DISPLAY_OPTIONS = (
    TimeDisplayOption(
        key="friendly_local_12",
        label="Friendly local (12-hour)",
        format_string="M j, Y g:i A",
    ),
    TimeDisplayOption(
        key="local_24",
        label="Local (24-hour)",
        format_string="Y-m-d H:i",
    ),
    TimeDisplayOption(
        key="utc_24",
        label="UTC (24-hour)",
        format_string="Y-m-d H:i",
        use_utc=True,
        suffix=" UTC",
    ),
)

DEFAULT_TIME_DISPLAY_OPTION = TIME_DISPLAY_OPTIONS[0].key
_OPTIONS_BY_KEY = {option.key: option for option in TIME_DISPLAY_OPTIONS}


def get_time_display_option(request) -> str:
    if request is None:
        return DEFAULT_TIME_DISPLAY_OPTION

    selected = request.session.get(TIME_DISPLAY_SESSION_KEY, DEFAULT_TIME_DISPLAY_OPTION)
    if selected in _OPTIONS_BY_KEY:
        return selected
    return DEFAULT_TIME_DISPLAY_OPTION


def get_time_display_definition(option_key: str | None) -> TimeDisplayOption:
    if option_key in _OPTIONS_BY_KEY:
        return _OPTIONS_BY_KEY[option_key]
    return _OPTIONS_BY_KEY[DEFAULT_TIME_DISPLAY_OPTION]


def get_time_display_context(request):
    selected = get_time_display_option(request)
    return {
        "time_display_option": selected,
        "time_display_choices": TIME_DISPLAY_OPTIONS,
    }


def get_intel_local_timezone():
    tz_name = getattr(settings, "INTEL_LOCAL_TIME_ZONE", "America/New_York")
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return ZoneInfo("America/New_York")
