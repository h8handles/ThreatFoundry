from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0010_domainenrichment"),
    ]

    # Compatibility branch retained for already-applied histories.
    # Canonical scoring schema is defined in
    # 0011_intelioc_calculated_score_intelioc_score_breakdown_and_more.
    operations = []
