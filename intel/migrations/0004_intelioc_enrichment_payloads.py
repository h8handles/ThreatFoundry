from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0003_align_model_state"),
    ]

    operations = [
        migrations.AddField(
            model_name="intelioc",
            name="enrichment_payloads",
            field=models.JSONField(blank=True, default=dict),
        ),
    ]
