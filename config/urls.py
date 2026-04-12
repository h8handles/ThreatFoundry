from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path

from intel.views_auth import (
    ThreatFoundryLoginView,
    ThreatFoundryRegisterView,
    permission_denied_view,
)

handler403 = permission_denied_view

urlpatterns = [
    path("auth/login/", ThreatFoundryLoginView.as_view(), name="login"),
    path("auth/register/", ThreatFoundryRegisterView.as_view(), name="register"),
    path("auth/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", include("intel.urls")),
    path("admin/", admin.site.urls),
]
