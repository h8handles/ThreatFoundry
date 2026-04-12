from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0004_intelioc_enrichment_payloads"),
    ]

    operations = [
        migrations.AddField(
            model_name="intelioc",
            name="external_references",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="last_enriched_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="last_enrichment_providers",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
