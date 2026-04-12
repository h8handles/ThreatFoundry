import os
from pathlib import Path

try:
    from dotenv import load_dotenv as _load_dotenv
except ImportError:  # pragma: no cover - optional convenience dependency
    def _load_dotenv(dotenv_path=None, *args, **kwargs):
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

        return True


PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_PATH = PROJECT_ROOT / ".env"


def load_project_env() -> bool:
    """Load the repo's .env file so standalone service scripts work locally."""
    return bool(_load_dotenv(ENV_PATH))
