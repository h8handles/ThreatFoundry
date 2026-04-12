from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("intel", "0005_intelioc_external_references_and_enrichment_tracking"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProviderRun",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("provider_name", models.CharField(max_length=100)),
                ("run_type", models.CharField(choices=[("ingest", "Ingest"), ("enrichment", "Enrichment")], max_length=20)),
                ("status", models.CharField(choices=[("success", "Success"), ("failure", "Failure"), ("partial", "Partial"), ("skipped", "Skipped")], max_length=20)),
                ("enabled_state", models.BooleanField(blank=True, null=True)),
                ("started_at", models.DateTimeField()),
                ("completed_at", models.DateTimeField(blank=True, null=True)),
                ("last_error_message", models.CharField(blank=True, max_length=500)),
                ("records_fetched", models.IntegerField(default=0)),
                ("records_created", models.IntegerField(default=0)),
                ("records_updated", models.IntegerField(default=0)),
                ("records_skipped", models.IntegerField(default=0)),
                ("details", models.JSONField(blank=True, default=dict)),
            ],
            options={
                "ordering": ["-started_at", "-id"],
            },
        ),
        migrations.AddIndex(
            model_name="providerrun",
            index=models.Index(fields=["provider_name", "-started_at"], name="intel_provi_provide_d17a11_idx"),
        ),
        migrations.AddIndex(
            model_name="providerrun",
            index=models.Index(fields=["run_type", "status"], name="intel_provi_run_typ_5467ea_idx"),
        ),
    ]
