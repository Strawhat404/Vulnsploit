from rest_framework import serializers
from django.contrib.auth.models import User
from .models import (
    UserProfile, APIKey, Target, ScheduledScan, ScanResult, ReconSession, ScanReport,
    Organization, OrganizationMember, AuditLog, WebhookEndpoint,
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


class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model  = Target
        fields = [
            'id', 'name', 'value', 'target_type', 'criticality', 'tags',
            'notes', 'organization', 'created_at', 'last_scanned_at',
        ]
        read_only_fields = ['id', 'created_at', 'last_scanned_at']


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


class ScheduledScanSerializer(serializers.ModelSerializer):
    class Meta:
        model  = ScheduledScan
        fields = ['id', 'target', 'scan_type', 'cron', 'is_active', 'organization',
                  'last_run_at', 'next_run_at', 'created_at']
        read_only_fields = ['id', 'last_run_at', 'next_run_at', 'created_at']


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
