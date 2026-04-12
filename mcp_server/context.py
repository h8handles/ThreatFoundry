from __future__ import annotations

import os
from pathlib import Path
from typing import Any


class ProjectContext:
    def __init__(self) -> None:
        self.root_dir = Path(__file__).resolve().parent.parent
        self._django_ready = False

    def ensure_django(self) -> None:
        if self._django_ready:
            return

        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
        import django

        django.setup()
        self._django_ready = True

    def safe_path(self, user_path: str) -> Path:
        candidate = (self.root_dir / user_path).resolve()
        if not str(candidate).startswith(str(self.root_dir.resolve())):
            raise ValueError("path escapes project root")
        return candidate

    def as_json_error(self, code: str, message: str, details: Any | None = None) -> dict:
        payload = {"ok": False, "error": {"code": code, "message": message}}
        if details is not None:
            payload["error"]["details"] = details
        return payload


CTX = ProjectContext()
