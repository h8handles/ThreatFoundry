from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable


SAFE_ARG_RE = re.compile(r"^[\w@%+=:,./\-]+$")


def to_compact_json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True, default=str)


def normalize_limit(raw_value: object, *, default: int, minimum: int, maximum: int) -> int:
    if raw_value is None:
        return default
    try:
        parsed = int(raw_value)
    except (TypeError, ValueError):
        return default
    if parsed < minimum:
        return minimum
    if parsed > maximum:
        return maximum
    return parsed


def validate_safe_args(args: Iterable[str]) -> list[str]:
    safe: list[str] = []
    for arg in args:
        if not isinstance(arg, str):
            raise ValueError("arguments must be strings")
        if not SAFE_ARG_RE.fullmatch(arg):
            raise ValueError(f"invalid argument: {arg!r}")
        safe.append(arg)
    return safe


def truncate_text(text: str, *, max_chars: int) -> str:
    if len(text) <= max_chars:
        return text
    return text[: max_chars - 3] + "..."


def rel_path(path: Path, root: Path) -> str:
    return str(path.resolve().relative_to(root.resolve())).replace("\\", "/")
