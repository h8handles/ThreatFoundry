from __future__ import annotations

import csv
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


class _Echo:
    def write(self, value: str) -> str:
        return value


def iter_csv_lines(header, row_iterable):
    writer = csv.writer(_Echo())
    yield writer.writerow(sanitize_csv_row(header))
    for row in row_iterable:
        yield writer.writerow(sanitize_csv_row(row))
