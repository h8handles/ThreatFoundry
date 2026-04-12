from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0001_initial"),
    ]

    operations = [
        migrations.RenameModel(
            old_name="ThreatFoxIOC",
            new_name="IntelIOC",
        ),
        migrations.RenameField(
            model_name="intelioc",
            old_name="threatfox_id",
            new_name="source_record_id",
        ),
        migrations.RenameField(
            model_name="intelioc",
            old_name="ioc",
            new_name="value",
        ),
        migrations.RenameField(
            model_name="intelioc",
            old_name="ioc_type",
            new_name="value_type",
        ),
        migrations.RenameField(
            model_name="intelioc",
            old_name="malware",
            new_name="malware_family",
        ),
        migrations.AlterField(
            model_name="intelioc",
            name="source_record_id",
            field=models.CharField(max_length=100),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="last_ingested_at",
            field=models.DateTimeField(auto_now=True, default=None),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="intelioc",
            name="raw_payload",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="reference_url",
            field=models.URLField(blank=True, default=""),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="intelioc",
            name="source_name",
            field=models.CharField(default="threatfox", max_length=100),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name="intelioc",
            name="updated_at",
            field=models.DateTimeField(auto_now=True, default=None),
            preserve_default=False,
        ),
        migrations.AlterField(
            model_name="intelioc",
            name="tags",
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddConstraint(
            model_name="intelioc",
            constraint=models.UniqueConstraint(
                fields=("source_name", "source_record_id"),
                name="unique_source_record",
            ),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(fields=["value"], name="intel_intel_value_64c59d_idx"),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(
                fields=["value_type"], name="intel_intel_value_t_2c4dae_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(
                fields=["source_name"], name="intel_intel_source__ff92fa_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(
                fields=["threat_type"], name="intel_intel_threat__13a70f_idx"
            ),
        ),
        migrations.AddIndex(
            model_name="intelioc",
            index=models.Index(
                fields=["malware_family"], name="intel_intel_malware_6836ba_idx"
            ),
        ),
    ]
