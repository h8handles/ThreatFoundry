from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0010_domainenrichment"),
    ]

    operations = [
        migrations.AddField(
            model_name="intelioc",
            name="calculated_score",
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="score_breakdown",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="intelioc",
            name="score_version",
            field=models.CharField(blank=True, default="", max_length=32),
        ),
    ]
