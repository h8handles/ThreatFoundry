from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0008_seed_default_auth_groups"),
    ]

    operations = [
        migrations.AddField(
            model_name="intelioc",
            name="correlation_reasons",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="derived_confidence_level",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="likely_malware_family",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="likely_threat_type",
            field=models.CharField(blank=True, max_length=255),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(fields=["derived_confidence_level"], name="intel_intel_derived_102a17_idx"),
        ),
    ]
