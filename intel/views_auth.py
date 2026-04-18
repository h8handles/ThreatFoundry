import time

from django.conf import settings
from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Group
from django.contrib.auth.views import LoginView
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import redirect, render
from django.views.generic import FormView

from intel.access import VIEWER_GROUP

_RATE_LIMIT_WINDOW_SECONDS = 60
_AUTH_RATE_LIMIT_MAX_REQUESTS = 10
_AUTH_RATE_LIMIT: dict[str, list[float]] = {}


def _rate_limit_key(request) -> str:
    user_part = f"user:{request.user.pk}" if request.user.is_authenticated else "anon"
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    ip_part = forwarded_for.split(",", 1)[0].strip() or request.META.get("REMOTE_ADDR", "")
    return f"{user_part}:{ip_part}"


def _is_rate_limited(request) -> bool:
    now = time.time()
    key = _rate_limit_key(request)
    _AUTH_RATE_LIMIT[key] = [ts for ts in _AUTH_RATE_LIMIT.get(key, []) if now - ts < _RATE_LIMIT_WINDOW_SECONDS]
    if len(_AUTH_RATE_LIMIT[key]) >= _AUTH_RATE_LIMIT_MAX_REQUESTS:
        return True
    _AUTH_RATE_LIMIT[key].append(now)
    return False


class ThreatFoundryLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True

    def dispatch(self, request, *args, **kwargs):
        if _is_rate_limited(request):
            return JsonResponse({"ok": False, "error": "Too many authentication requests."}, status=429)
        return super().dispatch(request, *args, **kwargs)


class ThreatFoundryRegisterView(FormView):
    template_name = "registration/register.html"
    form_class = UserCreationForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("intel:dashboard")
        if not getattr(settings, "ENABLE_PUBLIC_REGISTRATION", False):
            return HttpResponseForbidden("Public registration is disabled.")
        if _is_rate_limited(request):
            return JsonResponse({"ok": False, "error": "Too many registration requests."}, status=429)
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
        viewer_group, _ = Group.objects.get_or_create(name=VIEWER_GROUP)
        user.groups.add(viewer_group)
        login(self.request, user)
        return redirect("intel:dashboard")


def permission_denied_view(request, exception=None):
    return render(request, "403.html", status=403)
