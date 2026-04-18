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

RUNSERVER_HOST = os.getenv("DJANGO_RUNSERVER_HOST", "172.30.150.130")
RUNSERVER_PORT = os.getenv("DJANGO_RUNSERVER_PORT", "8080")

DEBUG = os.getenv("DJANGO_DEBUG", "false").lower() == "true"


def _parse_csv_env(value):
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _text_env(value, default=""):
    text = (value or "").strip()
    return text or default


def _build_allowed_hosts(raw_hosts, *, debug, runserver_host):
    configured_hosts = _parse_csv_env(raw_hosts)
    if configured_hosts:
        return configured_hosts
    if debug:
        # Keep local development and tunnel access working unless the user
        # explicitly opts into a stricter host allowlist.
        return ["*"]
    return _parse_csv_env(f"localhost,127.0.0.1,{runserver_host}")


def _build_csrf_trusted_origins(raw_origins, *, runserver_host, runserver_port):
    configured_origins = _parse_csv_env(raw_origins)
    if configured_origins:
        return configured_origins
    return _parse_csv_env(
        ",".join(
            (
                f"http://localhost:{runserver_port}",
                f"http://127.0.0.1:{runserver_port}",
                f"http://{runserver_host}:{runserver_port}",
            )
        )
    )


SECRET_KEY = os.getenv("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if DEBUG:
        SECRET_KEY = "insecure-dev-key-change-before-shared-use"
    else:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY is required when DJANGO_DEBUG is false."
        )
ALLOWED_HOSTS = _build_allowed_hosts(
    os.getenv("DJANGO_ALLOWED_HOSTS"),
    debug=DEBUG,
    runserver_host=RUNSERVER_HOST,
)
CSRF_TRUSTED_ORIGINS = _build_csrf_trusted_origins(
    os.getenv("DJANGO_CSRF_TRUSTED_ORIGINS"),
    runserver_host=RUNSERVER_HOST,
    runserver_port=RUNSERVER_PORT,
)

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
    "config.security_headers.ContentSecurityPolicyMiddleware",
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
                "intel.context_processors.auth_access",
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
INTEL_REFRESH_LOG_FILE = _text_env(
    os.getenv("INTEL_REFRESH_LOG_FILE"),
    str(BASE_DIR / "var" / "log" / "refresh_intel.log"),
)
INTEL_REFRESH_LOCK_FILE = _text_env(
    os.getenv("INTEL_REFRESH_LOCK_FILE"),
    str(BASE_DIR / "var" / "run" / "refresh_intel.lock"),
)
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
INTEL_CHAT_CONTEXT_API_TOKEN = os.getenv("INTEL_CHAT_CONTEXT_API_TOKEN", "")
INTEL_CHAT_CONTEXT_API_TOKEN_HASH = os.getenv("INTEL_CHAT_CONTEXT_API_TOKEN_HASH", "")
INTEL_ALLOWED_WEBHOOK_HOSTS = _parse_csv_env(os.getenv("INTEL_ALLOWED_WEBHOOK_HOSTS", ""))
INTEL_CHAT_INCLUDE_SYSTEM_PROMPT = os.getenv("INTEL_CHAT_INCLUDE_SYSTEM_PROMPT", "false").lower() == "true"
ENABLE_PUBLIC_REGISTRATION = os.getenv("ENABLE_PUBLIC_REGISTRATION", "false").lower() == "true"
ENABLE_EXPERIMENTAL_HUNTS = os.getenv("ENABLE_EXPERIMENTAL_HUNTS", "false").lower() == "true"

if not DEBUG:
    SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "true").lower() == "true"
    CSRF_COOKIE_SECURE = os.getenv("CSRF_COOKIE_SECURE", "true").lower() == "true"
    SECURE_SSL_REDIRECT = os.getenv("SECURE_SSL_REDIRECT", "true").lower() == "true"
    SECURE_HSTS_SECONDS = int(os.getenv("SECURE_HSTS_SECONDS", "31536000"))
    SECURE_CONTENT_TYPE_NOSNIFF = os.getenv("SECURE_CONTENT_TYPE_NOSNIFF", "true").lower() == "true"
    SECURE_REFERRER_POLICY = os.getenv("SECURE_REFERRER_POLICY", "same-origin")
    CONTENT_SECURITY_POLICY = {
        "DIRECTIVES": {
            "default-src": ("'self'",),
            "script-src": ("'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"),
            "style-src": ("'self'", "'unsafe-inline'"),
        }
    }

STATIC_URL = "static/"
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "intel:dashboard"
LOGOUT_REDIRECT_URL = "login"
