from intel.time_display import get_time_display_context


def time_display_preferences(request):
    return get_time_display_context(request)

