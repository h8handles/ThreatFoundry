import os
from pathlib import Path
from django.core.exceptions import ImproperlyConfigured

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    def load_dotenv(dotenv_path=None, *args, **kwargs):
        if not dotenv_path:
            return False

        env_path = Path(dotenv_path)
        if not env_path.exists():
            return False

        for line in env_path.read_text().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue

            key, value = stripped.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip())

        return False


BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")

DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"
SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "insecure-dev-key-change-before-shared-use"
    else:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY is required when DJANGO_DEBUG is false."
        )
ALLOWED_HOSTS = [
    host.strip()
    for host in os.getenv("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")
    if host.strip()
]
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "intel",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "config.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "intel.context_processors.time_display_preferences",
            ],
        },
    },
]

WSGI_APPLICATION = "config.wsgi.application"
ASGI_APPLICATION = "config.asgi.application"

if os.getenv("POSTGRES_DB"):
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.postgresql",
            "NAME": os.getenv("POSTGRES_DB", ""),
            "USER": os.getenv("POSTGRES_USER", ""),
            "PASSWORD": os.getenv("POSTGRES_PASSWORD", ""),
            "HOST": os.getenv("POSTGRES_HOST", "localhost"),
            "PORT": os.getenv("POSTGRES_PORT", "5432"),
        }
    }
else:
    DATABASES = {
        "default": {
            "ENGINE": "django.db.backends.sqlite3",
            "NAME": BASE_DIR / "db.sqlite3",
        }
    }

LANGUAGE_CODE = "en-us"
TIME_ZONE = os.getenv("DJANGO_TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True
INTEL_LOCAL_TIME_ZONE = os.getenv("INTEL_LOCAL_TIME_ZONE", "America/New_York")

INTEL_REFRESH_SCHEDULE = os.getenv("INTEL_REFRESH_SCHEDULE", "0 2 * * *")
INTEL_REFRESH_DEFAULT_SINCE = os.getenv("INTEL_REFRESH_DEFAULT_SINCE", "24h")
INTEL_REFRESH_TIMEOUT = int(os.getenv("INTEL_REFRESH_TIMEOUT", "30"))
INTEL_REFRESH_VIRUSTOTAL_LIMIT = int(
    os.getenv("INTEL_REFRESH_VIRUSTOTAL_LIMIT", "25")
)
INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS = float(
    os.getenv("INTEL_REFRESH_VIRUSTOTAL_THROTTLE_SECONDS", "16")
)
INTEL_CHAT_PROVIDER = os.getenv("INTEL_CHAT_PROVIDER", "hybrid")
INTEL_CHAT_MAX_CONTEXT_RECORDS = int(os.getenv("INTEL_CHAT_MAX_CONTEXT_RECORDS", "60"))
INTEL_CHAT_N8N_WEBHOOK_URL = os.getenv("INTEL_CHAT_N8N_WEBHOOK_URL", "")
INTEL_CHAT_N8N_TIMEOUT = int(os.getenv("INTEL_CHAT_N8N_TIMEOUT", "20"))
INTEL_CHAT_N8N_BEARER_TOKEN = os.getenv("INTEL_CHAT_N8N_BEARER_TOKEN", "")

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
