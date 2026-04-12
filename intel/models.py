from django.db import models


class IntelIOC(models.Model):
    """
    Minimal normalized IOC table for the current project phase.

    We keep one row per source record for now, which is enough to prove the
    ingestion pipeline on a single source before expanding to a richer schema.
    """

    # Feed identity lets us support many free sources later.
    source_name = models.CharField(max_length=100)
    source_record_id = models.CharField(max_length=100)

    # These are the main analyst-facing IOC fields we want to study first.
    value = models.CharField(max_length=255)
    value_type = models.CharField(max_length=50)
    threat_type = models.CharField(max_length=100, blank=True)
    malware_family = models.CharField(max_length=100, blank=True)
    confidence_level = models.IntegerField(null=True, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    reporter = models.CharField(max_length=100, blank=True)
    reference_url = models.URLField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    external_references = models.JSONField(default=list, blank=True)

    # We keep the full original source row so we can revisit dropped details.
    raw_payload = models.JSONField(default=dict, blank=True)
    enrichment_payloads = models.JSONField(default=dict, blank=True)
    last_enriched_at = models.DateTimeField(null=True, blank=True)
    last_enrichment_providers = models.JSONField(default=list, blank=True)

    # Local timestamps help us track what the app has done with the record.
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_ingested_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=["source_name", "source_record_id"],
                name="unique_source_record",
            )
        ]
        indexes = [
            models.Index(fields=["value"]),
            models.Index(fields=["value_type"]),
            models.Index(fields=["source_name"]),
            models.Index(fields=["threat_type"]),
            models.Index(fields=["malware_family"]),
        ]
        ordering = ["-last_seen", "-first_seen", "value"]

    def __str__(self):
        return f"{self.source_name} {self.value_type}: {self.value}"


class ProviderRun(models.Model):
    class RunType(models.TextChoices):
        INGEST = "ingest", "Ingest"
        ENRICHMENT = "enrichment", "Enrichment"

    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"
        PARTIAL = "partial", "Partial"
        SKIPPED = "skipped", "Skipped"

    provider_name = models.CharField(max_length=100)
    run_type = models.CharField(max_length=20, choices=RunType.choices)
    status = models.CharField(max_length=20, choices=Status.choices)
    enabled_state = models.BooleanField(null=True, blank=True)
    started_at = models.DateTimeField()
    completed_at = models.DateTimeField(null=True, blank=True)
    last_error_message = models.CharField(max_length=500, blank=True)
    records_fetched = models.IntegerField(default=0)
    records_created = models.IntegerField(default=0)
    records_updated = models.IntegerField(default=0)
    records_skipped = models.IntegerField(default=0)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [
            models.Index(fields=["provider_name", "-started_at"]),
            models.Index(fields=["run_type", "status"]),
        ]

    def __str__(self):
        return f"{self.provider_name} {self.run_type} {self.status} @ {self.started_at.isoformat()}"


class IngestionRun(models.Model):
    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        PARTIAL = "partial", "Partial"
        FAILURE = "failure", "Failure"

    status = models.CharField(max_length=20, choices=Status.choices)
    trigger = models.CharField(max_length=50, default="manual")
    requested_provider = models.CharField(max_length=100, blank=True)
    requested_since = models.CharField(max_length=100, blank=True)
    timeout_seconds = models.IntegerField(default=30)
    dry_run = models.BooleanField(default=False)
    feed_refreshed = models.BooleanField(default=True)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    providers_total = models.IntegerField(default=0)
    providers_succeeded = models.IntegerField(default=0)
    providers_failed = models.IntegerField(default=0)
    providers_skipped = models.IntegerField(default=0)
    records_created = models.IntegerField(default=0)
    records_updated = models.IntegerField(default=0)
    records_skipped = models.IntegerField(default=0)
    error_summary = models.CharField(max_length=500, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-started_at", "-id"]
        indexes = [
            models.Index(fields=["status", "-started_at"]),
            models.Index(fields=["trigger", "-started_at"]),
        ]

    def __str__(self):
        return f"refresh_intel {self.status} @ {self.started_at.isoformat()}"


class ProviderRunDetail(models.Model):
    class RunType(models.TextChoices):
        INGEST = "ingest", "Ingest"
        ENRICHMENT = "enrichment", "Enrichment"

    class Status(models.TextChoices):
        SUCCESS = "success", "Success"
        FAILURE = "failure", "Failure"
        PARTIAL = "partial", "Partial"
        SKIPPED = "skipped", "Skipped"

    ingestion_run = models.ForeignKey(
        IngestionRun,
        on_delete=models.CASCADE,
        related_name="provider_details",
    )
    provider_name = models.CharField(max_length=100)
    run_type = models.CharField(max_length=20, choices=RunType.choices)
    enabled_state = models.BooleanField(null=True, blank=True)
    status = models.CharField(max_length=20, choices=Status.choices)
    started_at = models.DateTimeField()
    finished_at = models.DateTimeField(null=True, blank=True)
    records_fetched = models.IntegerField(default=0)
    records_created = models.IntegerField(default=0)
    records_updated = models.IntegerField(default=0)
    records_skipped = models.IntegerField(default=0)
    error_summary = models.CharField(max_length=500, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["started_at", "id"]
        indexes = [
            models.Index(fields=["ingestion_run", "provider_name"]),
            models.Index(fields=["provider_name", "-started_at"]),
            models.Index(fields=["run_type", "status"]),
        ]

    def __str__(self):
        return f"{self.provider_name} {self.status} @ {self.started_at.isoformat()}"
