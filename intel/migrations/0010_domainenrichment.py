from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("intel", "0009_intelioc_correlation_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="DomainEnrichment",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("registrar", models.CharField(blank=True, max_length=255)),
                ("creation_date", models.DateTimeField(blank=True, null=True)),
                ("updated_date", models.DateTimeField(blank=True, null=True)),
                ("expiration_date", models.DateTimeField(blank=True, null=True)),
                ("registrant_org", models.CharField(blank=True, max_length=255)),
                ("nameservers", models.JSONField(blank=True, default=list)),
                ("status_values", models.JSONField(blank=True, default=list)),
                ("abuse_contact_email", models.EmailField(blank=True, max_length=254)),
                ("a_records", models.JSONField(blank=True, default=list)),
                ("aaaa_records", models.JSONField(blank=True, default=list)),
                ("mx_records", models.JSONField(blank=True, default=list)),
                ("ns_records", models.JSONField(blank=True, default=list)),
                ("txt_records", models.JSONField(blank=True, default=list)),
                ("cname", models.CharField(blank=True, max_length=255)),
                ("cert_issuer", models.CharField(blank=True, max_length=255)),
                ("cert_subject", models.CharField(blank=True, max_length=255)),
                ("cert_san", models.JSONField(blank=True, default=list)),
                ("cert_valid_from", models.DateTimeField(blank=True, null=True)),
                ("cert_valid_to", models.DateTimeField(blank=True, null=True)),
                ("cert_sha256", models.CharField(blank=True, max_length=64)),
                ("root_domain", models.CharField(blank=True, max_length=255)),
                ("subdomain", models.CharField(blank=True, max_length=255)),
                ("tld", models.CharField(blank=True, max_length=50)),
                ("resolved_ips", models.JSONField(blank=True, default=list)),
                ("registrar_overlap", models.BooleanField(default=False)),
                ("nameserver_overlap", models.BooleanField(default=False)),
                ("domain_age_days", models.IntegerField(blank=True, null=True)),
                ("reputation_sources", models.JSONField(blank=True, default=list)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "ioc",
                    models.ForeignKey(
                        on_delete=models.deletion.CASCADE,
                        related_name="domain_enrichments",
                        to="intel.intelioc",
                    ),
                ),
            ],
            options={
                "unique_together": {("ioc",)},
                "indexes": [
                    models.Index(fields=["registrar"], name="intel_domai_registr_dee03b_idx"),
                    models.Index(fields=["root_domain"], name="intel_domai_root_do_022be3_idx"),
                    models.Index(fields=["tld"], name="intel_domai_tld_b719f4_idx"),
                    models.Index(fields=["cert_sha256"], name="intel_domai_cert_sh_4bc088_idx"),
                ],
            },
        ),
    ]
