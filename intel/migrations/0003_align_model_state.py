from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0002_rebuild_ioc_model"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="intelioc",
            options={"ordering": ["-last_seen", "-first_seen", "value"]},
        ),
        migrations.RenameIndex(
            model_name="intelioc",
            old_name="intel_intel_value_64c59d_idx",
            new_name="intel_intel_value_1e2452_idx",
        ),
        migrations.RenameIndex(
            model_name="intelioc",
            old_name="intel_intel_value_t_2c4dae_idx",
            new_name="intel_intel_value_t_65bd7e_idx",
        ),
        migrations.RenameIndex(
            model_name="intelioc",
            old_name="intel_intel_source__ff92fa_idx",
            new_name="intel_intel_source__cd948d_idx",
        ),
        migrations.RenameIndex(
            model_name="intelioc",
            old_name="intel_intel_threat__13a70f_idx",
            new_name="intel_intel_threat__1c6099_idx",
        ),
        migrations.RenameIndex(
            model_name="intelioc",
            old_name="intel_intel_malware_6836ba_idx",
            new_name="intel_intel_malware_681baa_idx",
        ),
    ]
