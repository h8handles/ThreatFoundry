from django.contrib.auth import login
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import Group
from django.contrib.auth.views import LoginView
from django.shortcuts import redirect, render
from django.views.generic import FormView

from intel.access import VIEWER_GROUP


class ThreatFoundryLoginView(LoginView):
    template_name = "registration/login.html"
    redirect_authenticated_user = True


class ThreatFoundryRegisterView(FormView):
    template_name = "registration/register.html"
    form_class = UserCreationForm

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("intel:dashboard")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
        viewer_group, _ = Group.objects.get_or_create(name=VIEWER_GROUP)
        user.groups.add(viewer_group)
        login(self.request, user)
        return redirect("intel:dashboard")


def permission_denied_view(request, exception=None):
    return render(request, "403.html", status=403)
