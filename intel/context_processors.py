from intel.access import build_auth_context
from intel.time_display import get_time_display_context


def time_display_preferences(request):
    return get_time_display_context(request)


def auth_access(request):
    return {"authz": build_auth_context(request.user)}
