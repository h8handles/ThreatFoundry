from __future__ import annotations

from typing import Any

from intel.models import IntelIOC


SCORE_VERSION = "v1"


def build_score_fields(
    *,
    derived_confidence_level: int | None,
    confidence_level: int | None,
) -> dict[str, Any]:
    source_field = ""
    score = None

    if derived_confidence_level is not None:
        source_field = "derived_confidence_level"
        score = _bound_score(derived_confidence_level)
    elif confidence_level is not None:
        source_field = "confidence_level"
        score = _bound_score(confidence_level)

    return {
        "calculated_score": score,
        "score_breakdown": {
            "source_field": source_field,
            "derived_confidence_level": derived_confidence_level,
            "confidence_level": confidence_level,
            "calculated_score": score,
        },
        "score_version": SCORE_VERSION,
    }


def build_score_fields_for_ioc(record: IntelIOC) -> dict[str, Any]:
    return build_score_fields(
        derived_confidence_level=record.derived_confidence_level,
        confidence_level=record.confidence_level,
    )


def apply_score_fields(record: IntelIOC) -> list[str]:
    score_fields = build_score_fields_for_ioc(record)
    changed_fields: list[str] = []

    for field_name, value in score_fields.items():
        if getattr(record, field_name) != value:
            setattr(record, field_name, value)
            changed_fields.append(field_name)

    return changed_fields


def refresh_ioc_score(record: IntelIOC, *, save: bool = True) -> bool:
    changed_fields = apply_score_fields(record)
    if changed_fields and save:
        IntelIOC.objects.filter(pk=record.pk).update(
            **{field: getattr(record, field) for field in changed_fields}
        )
    return bool(changed_fields)


def _bound_score(value: int) -> int:
    return max(0, min(100, int(value)))
