from django.conf import settings
from django.db import models
from django.utils import timezone


class IntelIOC(models.Model):
    """
    Minimal normalized IOC table for the current project phase.

    We keep one row per source record for now, which is enough to prove the
    ingestion pipeline on a single source before expanding to a richer schema.
    """

    source_name = models.CharField(max_length=100)
    source_record_id = models.CharField(max_length=100)

    value = models.CharField(max_length=255)
    value_type = models.CharField(max_length=50)
    threat_type = models.CharField(max_length=100, blank=True)
    malware_family = models.CharField(max_length=100, blank=True)
    confidence_level = models.IntegerField(null=True, blank=True)
    derived_confidence_level = models.IntegerField(null=True, blank=True)
    first_seen = models.DateTimeField(null=True, blank=True)
    last_seen = models.DateTimeField(null=True, blank=True)
    reporter = models.CharField(max_length=100, blank=True)
    reference_url = models.TextField(blank=True)
    tags = models.JSONField(default=list, blank=True)
    external_references = models.JSONField(default=list, blank=True)
    likely_threat_type = models.CharField(max_length=255, blank=True)
    likely_malware_family = models.CharField(max_length=255, blank=True)
    correlation_reasons = models.JSONField(default=list, blank=True)

    raw_payload = models.JSONField(default=dict, blank=True)
    enrichment_payloads = models.JSONField(default=dict, blank=True)
    last_enriched_at = models.DateTimeField(null=True, blank=True)
    last_enrichment_providers = models.JSONField(default=list, blank=True)

    # ThreatFoundry house scoring
    calculated_score = models.FloatField(null=True, blank=True)
    score_breakdown = models.JSONField(default=dict, blank=True)
    score_version = models.CharField(max_length=50, blank=True)

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
            models.Index(fields=["derived_confidence_level"]),
            models.Index(fields=["calculated_score"]),
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


class DomainEnrichment(models.Model):
    """
    Stores enrichment data for domain IOCs. Each record is linked to a single
    IntelIOC instance that contains a domain indicator.
    """

    ioc = models.ForeignKey(
        IntelIOC,
        on_delete=models.CASCADE,
        related_name="domain_enrichments",
    )
    registrar = models.CharField(max_length=255, blank=True)
    creation_date = models.DateTimeField(null=True, blank=True)
    updated_date = models.DateTimeField(null=True, blank=True)
    expiration_date = models.DateTimeField(null=True, blank=True)
    registrant_org = models.CharField(max_length=255, blank=True)
    nameservers = models.JSONField(default=list, blank=True)
    status_values = models.JSONField(default=list, blank=True)
    abuse_contact_email = models.EmailField(blank=True)

    a_records = models.JSONField(default=list, blank=True)
    aaaa_records = models.JSONField(default=list, blank=True)
    mx_records = models.JSONField(default=list, blank=True)
    ns_records = models.JSONField(default=list, blank=True)
    txt_records = models.JSONField(default=list, blank=True)
    cname = models.CharField(max_length=255, blank=True)

    cert_issuer = models.CharField(max_length=255, blank=True)
    cert_subject = models.CharField(max_length=255, blank=True)
    cert_san = models.JSONField(default=list, blank=True)
    cert_valid_from = models.DateTimeField(null=True, blank=True)
    cert_valid_to = models.DateTimeField(null=True, blank=True)
    cert_sha256 = models.CharField(max_length=64, blank=True)

    root_domain = models.CharField(max_length=255, blank=True)
    subdomain = models.CharField(max_length=255, blank=True)
    tld = models.CharField(max_length=50, blank=True)
    resolved_ips = models.JSONField(default=list, blank=True)

    registrar_overlap = models.BooleanField(default=False)
    nameserver_overlap = models.BooleanField(default=False)
    domain_age_days = models.IntegerField(null=True, blank=True)

    reputation_sources = models.JSONField(default=list, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("ioc",)
        indexes = [
            models.Index(fields=["registrar"]),
            models.Index(fields=["root_domain"]),
            models.Index(fields=["tld"]),
            models.Index(fields=["cert_sha256"]),
        ]

    def __str__(self):
        return f"DomainEnrichment for {self.ioc.value}"


class Ticket(models.Model):
    class Status(models.TextChoices):
        OPEN = "open", "Open"
        IN_PROGRESS = "in_progress", "In Progress"
        BLOCKED = "blocked", "Blocked"
        RESOLVED = "resolved", "Resolved"
        CLOSED = "closed", "Closed"

    class Priority(models.TextChoices):
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    title = models.CharField(max_length=180)
    description = models.TextField(blank=True)
    status = models.CharField(max_length=20, choices=Status.choices, default=Status.OPEN)
    priority = models.CharField(max_length=20, choices=Priority.choices, default=Priority.MEDIUM)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="created_tickets",
    )
    assigned_to = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="assigned_tickets",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at", "-created_at", "title"]
        indexes = [
            models.Index(fields=["status", "-updated_at"]),
            models.Index(fields=["priority", "-updated_at"]),
            models.Index(fields=["assigned_to", "status"]),
        ]

    def __str__(self):
        return self.title


class TicketNote(models.Model):
    ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE, related_name="notes")
    body = models.TextField()
    author = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="ticket_notes",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["created_at", "id"]
        indexes = [
            models.Index(fields=["ticket", "created_at"]),
            models.Index(fields=["author", "-created_at"]),
        ]

    def __str__(self):
        created = self.created_at.isoformat() if self.created_at else "unsaved"
        return f"Note for {self.ticket_id} @ {created}"
