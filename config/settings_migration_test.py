from .settings import *  # noqa: F401,F403
import os
import tempfile
from pathlib import Path


# Isolated SQLite database used for migration smoke tests.
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": Path(
            os.getenv(
                "THREATFOUNDRY_MIGRATION_TEST_DB",
                Path(tempfile.gettempdir()) / "threatfoundry_migration_test.sqlite3",
            )
        ),
    }
}
