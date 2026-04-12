from __future__ import annotations

from datetime import date, datetime, time


FORMULA_PREFIXES = ("=", "+", "-", "@")


def sanitize_csv_cell(value) -> str:
    if value is None:
        text = ""
    elif isinstance(value, (datetime, date, time)):
        text = value.isoformat()
    else:
        text = str(value)

    first_non_whitespace = text.lstrip()
    if first_non_whitespace.startswith(FORMULA_PREFIXES):
        return f"'{text}"
    return text


def sanitize_csv_row(values) -> list[str]:
    return [sanitize_csv_cell(value) for value in values]
