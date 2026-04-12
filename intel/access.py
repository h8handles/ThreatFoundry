from functools import wraps

from django.conf import settings
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.views import redirect_to_login
from django.core.exceptions import PermissionDenied
from django.http import JsonResponse


ADMIN_GROUP = "admin"
ANALYST_GROUP = "analyst"
VIEWER_GROUP = "viewer"

DEFAULT_GROUPS = (ADMIN_GROUP, ANALYST_GROUP, VIEWER_GROUP)

ROLE_HIERARCHY = {
    VIEWER_GROUP: {VIEWER_GROUP, ANALYST_GROUP, ADMIN_GROUP},
    ANALYST_GROUP: {ANALYST_GROUP, ADMIN_GROUP},
    ADMIN_GROUP: {ADMIN_GROUP},
}


def get_user_group_names(user):
    if not getattr(user, "is_authenticated", False):
        return set()

    names = set(user.groups.values_list("name", flat=True))
    if user.is_staff or user.is_superuser:
        names.add(ADMIN_GROUP)
    return names


def user_has_minimum_role(user, minimum_role):
    allowed_roles = ROLE_HIERARCHY[minimum_role]
    return bool(get_user_group_names(user) & allowed_roles)


def get_primary_role(user):
    if user_has_minimum_role(user, ADMIN_GROUP):
        return ADMIN_GROUP
    if user_has_minimum_role(user, ANALYST_GROUP):
        return ANALYST_GROUP
    if user_has_minimum_role(user, VIEWER_GROUP):
        return VIEWER_GROUP
    return None


def build_auth_context(user):
    primary_role = get_primary_role(user)
    return {
        "primary_role": primary_role,
        "role_label": (primary_role or "unassigned").replace("-", " ").title(),
        "can_view_app": user_has_minimum_role(user, VIEWER_GROUP),
        "can_use_assistant": user_has_minimum_role(user, ANALYST_GROUP),
        "can_administer": user_has_minimum_role(user, ADMIN_GROUP),
    }


def role_required(minimum_role):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return redirect_to_login(
                    request.get_full_path(),
                    settings.LOGIN_URL,
                    REDIRECT_FIELD_NAME,
                )

            if not user_has_minimum_role(request.user, minimum_role):
                raise PermissionDenied

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator


def api_role_required(minimum_role):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            if not request.user.is_authenticated:
                return JsonResponse(
                    {"ok": False, "error": "Authentication required."},
                    status=401,
                )

            if not user_has_minimum_role(request.user, minimum_role):
                return JsonResponse(
                    {"ok": False, "error": "You do not have access to this endpoint."},
                    status=403,
                )

            return view_func(request, *args, **kwargs)

        return wrapped_view

    return decorator
