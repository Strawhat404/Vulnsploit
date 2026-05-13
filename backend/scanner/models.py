from django.db import models
from django.contrib.auth.models import User


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

    user         = models.ForeignKey(User, on_delete=models.CASCADE, related_name='recon_sessions')
    target       = models.CharField(max_length=255)
    status       = models.CharField(max_length=20, choices=Status.choices, default=Status.PENDING)
    created_at   = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

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
