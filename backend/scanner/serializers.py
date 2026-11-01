from rest_framework import serializers
from django.contrib.auth.models import User
from .netguard import UnsafeTarget, assert_public_url
from .validators import validate_target as _validate_target, validate_scan_type as _validate_scan_type
from rest_framework.exceptions import ValidationError as _DRFValidationError
from .models import (
    UserProfile, APIKey, Target, ScheduledScan, ScanResult, ReconSession, ScanReport,
    Organization, OrganizationMember, AuditLog, WebhookEndpoint, FindingStatus,
)


# ─── Organization serialization ────────────────────────────────────────────────

class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Organization
        fields = ['id', 'name', 'slug', 'owner', 'created_at']
        read_only_fields = ['id', 'owner', 'created_at']


class OrganizationMemberSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model  = OrganizationMember
        fields = ['id', 'organization', 'user', 'username', 'role', 'joined_at']
        read_only_fields = ['id', 'username', 'joined_at']


class AuditLogSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True, default='')

    class Meta:
        model  = AuditLog
        fields = ['id', 'username', 'organization', 'action', 'resource_type',
                  'resource_id', 'ip_address', 'user_agent', 'metadata', 'created_at']
        read_only_fields = fields


class WebhookEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model  = WebhookEndpoint
        fields = ['id', 'name', 'url', 'secret', 'events', 'is_active',
                  'organization', 'last_triggered_at', 'created_at']
        read_only_fields = ['id', 'last_triggered_at', 'created_at']
        extra_kwargs = {'secret': {'write_only': True}}

    def validate_url(self, value):
        try:
            assert_public_url(value)
        except UnsafeTarget as exc:
            raise serializers.ValidationError(str(exc))
        return value


class FindingStatusSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True, default='')

    class Meta:
        model  = FindingStatus
        fields = ['id', 'username', 'organization', 'target', 'fingerprint',
                  'decision', 'note', 'created_at', 'updated_at']
        read_only_fields = ['id', 'username', 'created_at', 'updated_at']


class TargetSerializer(serializers.ModelSerializer):
    verified = serializers.SerializerMethodField()
    covered_by = serializers.SerializerMethodField()
    verification_expires_at = serializers.SerializerMethodField()
    verification = serializers.SerializerMethodField()

    class Meta:
        model  = Target
        fields = [
            'id', 'name', 'value', 'target_type', 'criticality', 'tags',
            'notes', 'organization', 'created_at', 'last_scanned_at',
            'verified', 'covered_by', 'verification_method', 'verified_at',
            'verification_expires_at', 'verification_token', 'verification',
        ]
        read_only_fields = [
            'id', 'created_at', 'last_scanned_at', 'verified', 'covered_by',
            'verification_method', 'verified_at', 'verification_expires_at',
            'verification_token', 'verification',
        ]

    def validate_value(self, value):
        # Saving a target never contacts it, so names need not resolve yet;
        # IP literals and CIDR ranges that are internal are still refused.
        try:
            return _validate_target(value, resolve=False)
        except _DRFValidationError as exc:
            raise serializers.ValidationError(_unwrap(exc))

    def _status(self, obj):
        from .authorization import verification_status
        cache = self.__dict__.setdefault('_status_cache', {})
        if obj.pk not in cache:
            cache[obj.pk] = verification_status(obj)
        return cache[obj.pk]

    def get_verified(self, obj):
        return self._status(obj)['verified']

    def get_covered_by(self, obj):
        return self._status(obj)['covered_by']

    def get_verification_expires_at(self, obj):
        return self._status(obj)['expires_at']

    def get_verification(self, obj):
        from .netguard import host_of
        from .verification import challenge_instructions
        if obj.target_type == 'cidr' or ('/' in obj.value and '://' not in obj.value):
            return None
        host = host_of(obj.value)
        return challenge_instructions(host, obj.verification_token) if host else None


class ProfileSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(source='user.email', required=False)
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model  = UserProfile
        fields = ['username', 'email', 'notify_scan_complete', 'notify_report_ready']

    def update(self, instance, validated_data):
        user_data = validated_data.pop('user', {})
        if 'email' in user_data:
            instance.user.email = user_data['email']
            instance.user.save()
        return super().update(instance, validated_data)


def _unwrap(exc):
    """validators raise {'field': msg}; field-level validators want just msg."""
    detail = exc.detail
    if isinstance(detail, dict):
        detail = next(iter(detail.values()))
    return detail


def validate_cron_expression(value: str) -> str:
    """
    Standard 5-field cron, restricted to at most one run per hour so a
    schedule cannot be used to hammer a target or flood the queue.
    """
    from celery.schedules import crontab_parser

    fields = (value or '').split()
    if len(fields) != 5:
        raise serializers.ValidationError(
            'Cron must have 5 fields: minute hour day-of-month month day-of-week.'
        )
    minute, hour, dom, month, dow = fields

    if not minute.isdigit() or not 0 <= int(minute) <= 59:
        raise serializers.ValidationError(
            'Minute must be a single number 0-59 (scans may run at most once per hour).'
        )

    # (name, field, number of values, lowest value) — celery's crontab_parser
    # takes the count of values, not the maximum.
    for name, field, count, lowest in (('hour', hour, 24, 0), ('day-of-month', dom, 31, 1),
                                       ('month', month, 12, 1), ('day-of-week', dow, 7, 0)):
        try:
            crontab_parser(count, lowest).parse(field)
        except Exception:
            raise serializers.ValidationError(f'Invalid cron {name} field: {field!r}.')
    return ' '.join(fields)


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model  = ScheduledScan
        fields = ['id', 'target', 'scan_type', 'cron', 'is_active', 'organization',
                  'last_run_at', 'next_run_at', 'created_at', 'blocked_reason']
        read_only_fields = ['id', 'last_run_at', 'next_run_at', 'created_at', 'blocked_reason']

    blocked_reason = serializers.SerializerMethodField()

    def get_blocked_reason(self, obj):
        """Why this schedule cannot run right now (None when it can)."""
        from .authorization import authorize_target, TargetNotVerified
        try:
            authorize_target(obj.user, obj.organization, obj.target)
        except TargetNotVerified as exc:
            return str(exc.detail)
        return None

    def validate_target(self, value):
        try:
            return _validate_target(value)
        except _DRFValidationError as exc:
            raise serializers.ValidationError(_unwrap(exc))

    def validate_scan_type(self, value):
        try:
            return _validate_scan_type(value)
        except _DRFValidationError as exc:
            raise serializers.ValidationError(_unwrap(exc))

    def validate_cron(self, value):
        return validate_cron_expression(value)


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(min_length=8, required=True)


class CreateAPIKeySerializer(serializers.Serializer):
    name = serializers.CharField(max_length=100)

    def create(self, validated_data):
        request = self.context.get('request')
        obj, raw = APIKey.create_key(user=request.user, name=validated_data['name'])
        self._raw_key = raw
        return obj

    @property
    def raw_key(self):
        return getattr(self, '_raw_key', None)


class APIKeySerializer(serializers.ModelSerializer):
    class Meta:
        model  = APIKey
        fields = ['id', 'name', 'prefix', 'is_active', 'last_used_at', 'created_at']
        read_only_fields = ['id', 'prefix', 'last_used_at', 'created_at']


class ScanResultSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model  = ScanResult
        fields = [
            'id', 'username', 'target', 'scan_type', 'status',
            'result', 'result_json', 'organization', 'created_at',
            'completed_at', 'recon_session',
        ]
        read_only_fields = [
            'id', 'username', 'status', 'result', 'result_json',
            'created_at', 'completed_at', 'recon_session',
        ]


class ReconSessionSerializer(serializers.ModelSerializer):
    username         = serializers.CharField(source='user.username', read_only=True)
    completed_scans  = serializers.SerializerMethodField()
    total_scans      = serializers.SerializerMethodField()
    has_report       = serializers.SerializerMethodField()
    report_id        = serializers.SerializerMethodField()

    class Meta:
        model  = ReconSession
        fields = [
            'id', 'username', 'target', 'status',
            'created_at', 'completed_at',
            'completed_scans', 'total_scans',
            'has_report', 'report_id',
        ]
        read_only_fields = ['id', 'username', 'status', 'created_at', 'completed_at']

    def get_completed_scans(self, obj):
        return obj.scan_results.filter(status='completed').count()

    def get_total_scans(self, obj):
        return obj.scan_results.count()

    def get_has_report(self, obj):
        return hasattr(obj, 'report') and obj.report is not None

    def get_report_id(self, obj):
        if hasattr(obj, 'report') and obj.report:
            return obj.report.id
        return None


class ScanReportSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)
    pdf_url  = serializers.SerializerMethodField()

    class Meta:
        model  = ScanReport
        fields = [
            'id', 'username', 'target', 'status',
            'risk_level', 'severity_counts', 'findings_json',
            'created_at', 'generated_at', 'pdf_url', 'error_message',
        ]
        read_only_fields = fields

    def get_pdf_url(self, obj):
        if obj.pdf_file:
            request = self.context.get('request')
            url = obj.pdf_file.url
            # Local filesystem returns a relative '/media/...' path — absolutize it.
            # Remote storage (S3/R2) returns a fully-qualified pre-signed URL.
            if request and url.startswith('/'):
                return request.build_absolute_uri(url)
            return url
        return None


class RegisterSerializer(serializers.Serializer):
    username  = serializers.CharField(min_length=3, max_length=150)
    password  = serializers.CharField(min_length=8, write_only=True)
    password2 = serializers.CharField(min_length=8, write_only=True)

    def validate_username(self, value):
        from django.contrib.auth.models import User
        import re
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError('Username already taken.')
        if not re.match(r'^[a-zA-Z0-9_]+$', value):
            raise serializers.ValidationError(
                'Username may only contain letters, numbers, and underscores.'
            )
        return value

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError({'password2': 'Passwords do not match.'})
        return data

    def create(self, validated_data):
        from django.contrib.auth.models import User
        user = User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
        )
        UserProfile.objects.get_or_create(user=user)
        return user
