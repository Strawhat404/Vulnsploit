import secrets
import hashlib
from django.db import models
from django.contrib.auth.models import User


def generate_api_key():
    return f"vs_{secrets.token_hex(32)}"


def hash_api_key(key):
    return hashlib.sha256(key.encode()).hexdigest()


# ─── Multi-tenancy: Organizations ──────────────────────────────────────────────

class Organization(models.Model):
    name       = models.CharField(max_length=100)
    slug       = models.SlugField(unique=True)
    owner      = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_organizations')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.name


class OrganizationMember(models.Model):
    class Role(models.TextChoices):
        OWNER   = 'owner',   'Owner'
        ADMIN   = 'admin',   'Admin'
        ANALYST = 'analyst', 'Analyst'
        VIEWER  = 'viewer',  'Viewer'

    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    user         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    role         = models.CharField(max_length=20, choices=Role.choices, default=Role.VIEWER)
    joined_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ['organization', 'user']
        ordering = ['joined_at']

    def __str__(self):
        return f"{self.user.username} @ {self.organization.name} ({self.role})"


# ─── Compliance / activity audit log ──────────────────────────────────────────

class AuditLog(models.Model):
    user          = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    organization  = models.ForeignKey(Organization, on_delete=models.SET_NULL, null=True, blank=True)
    action        = models.CharField(max_length=100)              # 'POST /api/scans/'
    resource_type = models.CharField(max_length=50, blank=True)
    resource_id   = models.IntegerField(null=True, blank=True)
    ip_address    = models.GenericIPAddressField(null=True, blank=True)
    user_agent    = models.TextField(blank=True)
    metadata      = models.JSONField(default=dict, blank=True)
    created_at    = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.action} | {self.user} | {self.created_at:%Y-%m-%d %H:%M}"


class UserProfile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    notify_scan_complete = models.BooleanField(default=True)
    notify_report_ready  = models.BooleanField(default=True)
    created_at           = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Profile: {self.user.username}"


class APIKey(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='api_keys')
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='api_keys',
    )
    name = models.CharField(max_length=100)
    prefix = models.CharField(max_length=8, editable=False)
    key_hash = models.CharField(max_length=64, editable=False)
    is_active = models.BooleanField(default=True)
    last_used_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.prefix}...)"
    
    @classmethod
    def create_key(cls, user, name):
        raw = generate_api_key()
        obj = cls.objects.create(
            user=user,
            name=name,
            prefix=raw[:8],
            key_hash=hash_api_key(raw),
        )
        return obj, raw


class ScheduledScan(models.Model):
    SCAN_TYPES = [
        ('quick', 'Quick Scan'), ('full', 'Full Scan'), ('nikto', 'Nikto'),
        ('gobuster', 'Gobuster'), ('nuclei', 'Nuclei'), ('whatweb', 'WhatWeb'),
        ('subfinder', 'Subfinder'), ('wpscan', 'WPScan'), ('testssl', 'TestSSL'),
        ('headers', 'Headers Check'), ('sqlmap', 'SQLMap'),
        ('full_recon', 'Full Recon'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='scheduled_scans')
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='scheduled_scans',
    )
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=100, choices=SCAN_TYPES)
    cron = models.CharField(max_length=100, help_text='Cron expression (e.g. 0 2 * * 1)')
    is_active = models.BooleanField(default=True)
    last_run_at = models.DateTimeField(null=True, blank=True)
    next_run_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.target} ({self.scan_type}) — {self.cron}"


class Target(models.Model):
    class TargetType(models.TextChoices):
        DOMAIN = 'domain', 'Domain'
        IP = 'ip', 'IP Address'
        URL = 'url', 'URL'
        CIDR = 'cidr', 'CIDR Range'

    class Criticality(models.TextChoices):
        LOW      = 'low',      'Low'
        MEDIUM   = 'medium',   'Medium'
        HIGH     = 'high',     'High'
        CRITICAL = 'critical', 'Critical'

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='targets')
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='targets',
    )
    name = models.CharField(max_length=100)
    value = models.CharField(max_length=255)
    target_type = models.CharField(max_length=20, choices=TargetType.choices)
    criticality = models.CharField(max_length=20, choices=Criticality.choices, default=Criticality.MEDIUM)
    tags = models.JSONField(default=list)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_scanned_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']
        unique_together = ['user', 'value']

    def __str__(self):
        return f"{self.name} ({self.value})"


class ScanResult(models.Model):

    class Status(models.TextChoices):
        PENDING   = 'pending',   'Pending'
        RUNNING   = 'running',   'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED    = 'failed',    'Failed'

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='scans',
        null=True,
        blank=True,
    )
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='scans',
    )

    target    = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=100)
    url       = models.CharField(max_length=255, blank=True, null=True)

    status = models.CharField(
        max_length=20,
        choices=Status.choices,
        default=Status.PENDING,
    )

    created_at   = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    result      = models.TextField(blank=True, null=True)
    result_json = models.JSONField(blank=True, null=True)

    # Celery task ID for cancellation
    celery_task_id = models.CharField(max_length=255, blank=True, null=True)

    # Link to a recon session if part of a full recon
    recon_session = models.ForeignKey(
        'ReconSession',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan_results',
    )

    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', '-created_at']),
            models.Index(fields=['status']),
            models.Index(fields=['scan_type']),
            models.Index(fields=['-created_at']),
        ]

    def __str__(self):
        return f"{self.target} — {self.scan_type} [{self.status}]"


class ReconSession(models.Model):
    """
    Groups multiple ScanResult records for a full recon run against one target.
    """

    class Status(models.TextChoices):
        PENDING   = 'pending',   'Pending'
        RUNNING   = 'running',   'Running'
        COMPLETED = 'completed', 'Completed'
        FAILED    = 'failed',    'Failed'

    user            = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recon_sessions')
    organization    = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='recon_sessions',
    )
    target          = models.CharField(max_length=255)
    status          = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    celery_task_id  = models.CharField(max_length=255, blank=True, null=True)
    created_at      = models.DateTimeField(auto_now_add=True)
    completed_at    = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"ReconSession: {self.target} [{self.status}]"

    @property
    def progress(self):
        """Returns (completed_count, total_count)."""
        total     = self.scan_results.count()
        completed = self.scan_results.filter(status='completed').count()
        return completed, total


class ScanReport(models.Model):
    """
    Generated PDF report for a target — either from a ReconSession or ad-hoc scan list.
    """

    class Status(models.TextChoices):
        GENERATING = 'generating', 'Generating'
        READY      = 'ready',      'Ready'
        FAILED     = 'failed',     'Failed'

    user            = models.ForeignKey(User, on_delete=models.CASCADE, related_name='reports')
    organization    = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='reports',
    )
    target          = models.CharField(max_length=255)
    status          = models.CharField(max_length=20, choices=Status.choices, default=Status.GENERATING)
    recon_session   = models.OneToOneField(
        ReconSession,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='report',
    )
    # Ad-hoc scans (not from a full recon session)
    scan_results    = models.ManyToManyField(ScanResult, blank=True, related_name='reports')

    findings_json   = models.JSONField(blank=True, null=True)   # parsed + AI interpreted
    severity_counts = models.JSONField(blank=True, null=True)
    risk_level      = models.CharField(max_length=20, blank=True, null=True)
    pdf_file        = models.FileField(upload_to='reports/', blank=True, null=True)

    created_at  = models.DateTimeField(auto_now_add=True)
    generated_at = models.DateTimeField(null=True, blank=True)

    error_message = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"Report: {self.target} [{self.status}]"


# ─── Webhook integrations ──────────────────────────────────────────────────────

class WebhookEndpoint(models.Model):
    """
    Webhook endpoint for delivering alerts to Slack, Microsoft Teams,
    Discord, or any HTTP endpoint that accepts a JSON POST body.
    Each delivery is signed with an HMAC-SHA256 signature in the
    X-VulnSploit-Signature header so receivers can verify authenticity.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='webhooks')
    organization = models.ForeignKey(
        'Organization', on_delete=models.CASCADE, null=True, blank=True,
        related_name='webhooks',
    )
    name = models.CharField(max_length=100)
    url = models.URLField()
    secret = models.CharField(max_length=128, blank=True, help_text='HMAC signing secret')
    events = models.JSONField(
        default=list,
        help_text="List of event types: scan.completed, report.ready, "
                   "finding.new_critical, finding.new_high, posture.changed"
    )
    is_active = models.BooleanField(default=True)
    last_triggered_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} → {self.url[:60]}"
