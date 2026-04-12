from __future__ import annotations

from datetime import timezone as datetime_timezone

from django import template
from django.utils import timezone
from django.utils.formats import date_format

from intel.time_display import (
    get_intel_local_timezone,
    get_time_display_definition,
    get_time_display_option,
)


register = template.Library()


@register.simple_tag(takes_context=True)
def display_datetime(context, value, default="N/A"):
    if not value:
        return default

    request = context.get("request")
    selected_option = get_time_display_option(request)
    option = get_time_display_definition(selected_option)

    dt = value
    if timezone.is_naive(dt):
        dt = timezone.make_aware(dt, timezone.get_default_timezone())

    if option.use_utc:
        dt = timezone.localtime(dt, datetime_timezone.utc)
    else:
        dt = timezone.localtime(dt, get_intel_local_timezone())

    rendered = date_format(dt, option.format_string, use_l10n=False)
    if option.suffix:
        return f"{rendered}{option.suffix}"
    return rendered
