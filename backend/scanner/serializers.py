from rest_framework import serializers
from .models import ScanResult, ReconSession, ScanReport


class ScanResultSerializer(serializers.ModelSerializer):
    username = serializers.CharField(source='user.username', read_only=True)

    class Meta:
        model  = ScanResult
        fields = [
            'id', 'username', 'target', 'scan_type', 'status',
            'result', 'result_json', 'created_at', 'completed_at',
            'recon_session',
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
            if request:
                return request.build_absolute_uri(f'/media/{obj.pdf_file}')
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
        return User.objects.create_user(
            username=validated_data['username'],
            password=validated_data['password'],
        )
