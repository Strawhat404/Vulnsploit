import logging
import os
from rest_framework import generics, status, viewsets
from rest_framework import serializers as drf_serializers
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404, redirect
from django.http import FileResponse, Http404
from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.db import models as dj_models
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import (
    UserProfile, APIKey, Target, ScheduledScan, ScanResult, ReconSession, ScanReport,
    Organization, OrganizationMember, AuditLog,
)
from .serializers import (
    TargetSerializer, ScanResultSerializer, ReconSessionSerializer,
    ScanReportSerializer, RegisterSerializer, ProfileSerializer,
    ChangePasswordSerializer, CreateAPIKeySerializer, APIKeySerializer,
    ScheduledScanSerializer, OrganizationSerializer, OrganizationMemberSerializer,
    AuditLogSerializer,
)
from .tasks import execute_scan, execute_full_recon, generate_report
from .validators import validate_target, validate_scan_type

logger = logging.getLogger('scanner')


# ─── Multi-tenancy helpers ─────────────────────────────────────────────────────

def get_user_orgs(user):
    """Return the queryset of Organizations the user is a member of."""
    if not user or not user.is_authenticated:
        return Organization.objects.none()
    return Organization.objects.filter(memberships__user=user)


def org_scoped_queryset(model, user):
    """
    Objects shared in any org the user belongs to, plus private (no-org)
    objects owned by the user directly. Backward compatible with the
    single-user model — pre-existing rows have organization=None and are
    owned by user, so they remain visible to their owner.
    """
    user_orgs = get_user_orgs(user)
    return model.objects.filter(
        dj_models.Q(organization__in=user_orgs) |
        dj_models.Q(organization__isnull=True, user=user)
    )


def resolve_org(request):
    """
    Resolve an optional organization from request.data. Returns an
    Organization instance if a valid org id is provided AND the user is a
    member, else None (private to user).
    Raises a ValidationError if an org is provided but the user is not a member.
    """
    org_id = request.data.get('organization')
    if not org_id:
        return None
    user_orgs = get_user_orgs(request.user)
    try:
        return user_orgs.get(id=org_id)
    except Organization.DoesNotExist:
        raise drf_serializers.ValidationError(
            {'organization': 'Not a member of that organization.'}
        )


# ─── JWT with httpOnly cookie ───────────────────────────────────────────────────

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.settings import api_settings
from django.conf import settings as django_settings


class CookieTokenObtainPairView(TokenObtainPairView):
    def finalize_response(self, request, response, *args, **kwargs):
        if response.status_code == 200 and 'refresh' in response.data:
            refresh = response.data.pop('refresh')
            max_age = int(api_settings.REFRESH_TOKEN_LIFETIME.total_seconds())
            response.set_cookie(
                'refresh_token', refresh,
                max_age=max_age,
                httponly=True,
                secure=not django_settings.DEBUG,
                samesite='Lax',
                path='/api/token/refresh/',
            )
        return super().finalize_response(request, response, *args, **kwargs)


class CookieTokenRefreshView(TokenRefreshView):
    def finalize_response(self, request, response, *args, **kwargs):
        if response.status_code == 200 and 'refresh' in response.data:
            refresh = response.data.pop('refresh')
            max_age = int(api_settings.REFRESH_TOKEN_LIFETIME.total_seconds())
            response.set_cookie(
                'refresh_token', refresh,
                max_age=max_age,
                httponly=True,
                secure=not django_settings.DEBUG,
                samesite='Lax',
                path='/api/token/refresh/',
            )
        return super().finalize_response(request, response, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if 'refresh' not in request.data and 'refresh_token' in request.COOKIES:
            request.data._mutable = True
            request.data['refresh'] = request.COOKIES['refresh_token']
            request.data._mutable = False
        return super().post(request, *args, **kwargs)


# ─── User Stats ─────────────────────────────────────────────────────────────────

class UserStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = org_scoped_queryset(ScanResult, request.user)
        return Response({
            'total': scans.count(),
            'completed': scans.filter(status='completed').count(),
            'running': scans.filter(status__in=['running', 'pending']).count(),
            'failed': scans.filter(status='failed').count(),
            'recon_sessions': org_scoped_queryset(ReconSession, request.user).count(),
            'reports': org_scoped_queryset(ScanReport, request.user).count(),
        })


# ─── Targets ───────────────────────────────────────────────────────────────────

class TargetViewSet(viewsets.ModelViewSet):
    serializer_class   = TargetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(Target, self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user, organization=resolve_org(self.request))


# ─── Profile / Settings ────────────────────────────────────────────────────────

class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        return Response(ProfileSerializer(profile).data)

    def put(self, request):
        profile, _ = UserProfile.objects.get_or_create(user=request.user)
        serializer = ProfileSerializer(profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data['old_password']):
            return Response({'detail': 'Current password is incorrect.'}, status=status.HTTP_400_BAD_REQUEST)
        user.set_password(serializer.validated_data['new_password'])
        user.save()
        update_session_auth_hash(request, user)
        return Response({'detail': 'Password changed successfully.'})


# ─── API Keys ──────────────────────────────────────────────────────────────────

class APIKeyListView(generics.ListCreateAPIView):
    permission_classes = [IsAuthenticated]

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return CreateAPIKeySerializer
        return APIKeySerializer

    def get_queryset(self):
        user_orgs = get_user_orgs(self.request.user)
        return APIKey.objects.filter(
            dj_models.Q(organization__in=user_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )

    def get_serializer_context(self):
        return {'request': self.request}

    def create(self, request, *args, **kwargs):
        serializer = CreateAPIKeySerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        key_obj = serializer.save()
        return Response({
            **APIKeySerializer(key_obj).data,
            'raw_key': serializer.raw_key or f"vs_{key_obj.prefix}****",
        }, status=status.HTTP_201_CREATED)


class APIKeyDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class   = APIKeySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_orgs = get_user_orgs(self.request.user)
        return APIKey.objects.filter(
            dj_models.Q(organization__in=user_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )

    def perform_destroy(self, instance):
        instance.is_active = False
        instance.save()


# ─── Scan Cancellation ─────────────────────────────────────────────────────────

class CancelScanView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        scan = get_object_or_404(org_scoped_queryset(ScanResult, request.user), id=pk)
        if scan.status in ('pending', 'running') and scan.celery_task_id:
            from celery.app.control import Control
            from celery import current_app
            Control(current_app).revoke(scan.celery_task_id, terminate=True)
            scan.status = ScanResult.Status.FAILED
            scan.result = 'Cancelled by user'
            scan.save(update_fields=['status', 'result'])
        return Response({'status': 'cancelled'})


class CancelReconView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        session = get_object_or_404(org_scoped_queryset(ReconSession, request.user), id=pk)
        if session.status in ('pending', 'running') and session.celery_task_id:
            from celery.app.control import Control
            from celery import current_app
            Control(current_app).revoke(session.celery_task_id, terminate=True)
            session.status = ReconSession.Status.FAILED
            session.save(update_fields=['status'])
            for scan in session.scan_results.filter(status__in=['pending', 'running']):
                scan.status = ScanResult.Status.FAILED
                scan.result = 'Cancelled by user'
                scan.save(update_fields=['status', 'result'])
        return Response({'status': 'cancelled'})


# ─── Scheduled Scans ───────────────────────────────────────────────────────────

class ScheduledScanListCreateView(generics.ListCreateAPIView):
    serializer_class   = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScheduledScan, self.request.user)

    def perform_create(self, serializer):
        org = resolve_org(self.request)
        instance = serializer.save(user=self.request.user, organization=org)
        _create_beat_schedule(serializer, org, self.request.user)


class ScheduledScanDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class   = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScheduledScan, self.request.user)

    def perform_destroy(self, instance):
        _remove_beat_schedule(instance)
        instance.delete()

    def perform_update(self, serializer):
        instance = serializer.save()
        _remove_beat_schedule(instance)
        _create_beat_schedule(serializer, instance.organization, instance.user)


def _create_beat_schedule(serializer, org, user):
    """
    Create/update a django-celery-beat PeriodicTask entry (CrontabSchedule +
    PeriodicTask) so the scheduled scan actually fires via Celery Beat.
    """
    import json
    from django_celery_beat.models import CrontabSchedule, PeriodicTask

    instance = getattr(serializer, 'instance', None)
    if instance is None:
        return

    cron = (instance.cron or '').split()
    if len(cron) != 5:
        logger.warning("Scheduled scan %s has invalid cron: %r", instance.id, instance.cron)
        return

    # Standard cron order: minute hour day-of-month month-of-year day-of-week
    # django-celery-beat's CrontabSchedule field names follow the same order.
    schedule, _ = CrontabSchedule.objects.get_or_create(
        minute=cron[0], hour=cron[1],
        day_of_month=cron[2], month_of_year=cron[3],
        day_of_week=cron[4],
    )

    task_name = f"scheduled_scan_{instance.id}"
    kwargs = json.dumps({'scheduled_scan_id': instance.id})
    PeriodicTask.objects.update_or_create(
        name=task_name,
        defaults={
            'crontab': schedule,
            'task':    'scanner.tasks.run_scheduled_scan',
            'kwargs':  kwargs,
            'enabled': instance.is_active,
        },
    )


def _remove_beat_schedule(instance):
    from django_celery_beat.models import PeriodicTask
    PeriodicTask.objects.filter(name=f"scheduled_scan_{instance.id}").delete()


# ─── Pagination ────────────────────────────────────────────────────────────────

class ScanPagination(PageNumberPagination):
    page_size             = 20
    page_size_query_param = 'page_size'
    max_page_size         = 100


# ─── Registration ──────────────────────────────────────────────────────────────

@method_decorator(ratelimit(key='ip', rate='5/h', method='POST', block=True), name='post')
class RegisterView(generics.CreateAPIView):
    serializer_class   = RegisterSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        logger.info("New user registered: %s", user.username)
        return Response(
            {'detail': f"Account created for '{user.username}'. You can now log in."},
            status=status.HTTP_201_CREATED
        )


# ─── Scan list / create ────────────────────────────────────────────────────────

@method_decorator(ratelimit(key='user', rate='20/h', method='POST', block=True), name='post')
class ScanResultListCreateView(generics.ListCreateAPIView):
    serializer_class   = ScanResultSerializer
    pagination_class   = ScanPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScanResult, self.request.user)

    def perform_create(self, serializer):
        target    = self.request.data.get('target', '').strip()
        scan_type = self.request.data.get('scan_type', '').strip()

        validate_target(target)
        validate_scan_type(scan_type)
        org = resolve_org(self.request)

        scan = serializer.save(
            user         = self.request.user,
            organization = org,
            status       = ScanResult.Status.PENDING,
            result       = "Scan queued...",
        )
        task = execute_scan.delay(scan.id, target, scan_type)
        scan.celery_task_id = task.id
        scan.save(update_fields=['celery_task_id'])

        logger.info("Scan queued | id=%s target=%s type=%s user=%s",
                    scan.id, target, scan_type, self.request.user.username)

    def create(self, request, *args, **kwargs):
        try:
            return super().create(request, *args, **kwargs)
        except Exception as exc:
            if hasattr(exc, 'detail'):
                raise
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)


# ─── Scan detail ───────────────────────────────────────────────────────────────

class ScanResultDetailView(generics.RetrieveAPIView):
    serializer_class   = ScanResultSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScanResult, self.request.user)


# ─── Full Recon ────────────────────────────────────────────────────────────────

@method_decorator(ratelimit(key='user', rate='5/h', method='POST', block=True), name='post')
class FullReconView(APIView):
    """
    POST /api/recon/
    Launch a full recon session against a target (runs all tools).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        target = request.data.get('target', '').strip()

        try:
            validate_target(target)
        except Exception as exc:
            return Response({'detail': str(exc)}, status=status.HTTP_400_BAD_REQUEST)

        org = resolve_org(request)

        session = ReconSession.objects.create(
            user         = request.user,
            organization = org,
            target       = target,
            status       = ReconSession.Status.PENDING,
        )

        task = execute_full_recon.delay(session.id)
        session.celery_task_id = task.id
        session.save(update_fields=['celery_task_id'])

        logger.info("Full recon queued | session=%s target=%s user=%s",
                    session.id, target, request.user.username)

        return Response(
            ReconSessionSerializer(session).data,
            status=status.HTTP_201_CREATED
        )


class ReconSessionListView(generics.ListAPIView):
    """GET /api/recon/ — list user's recon sessions."""
    serializer_class   = ReconSessionSerializer
    pagination_class   = ScanPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ReconSession, self.request.user)


class ReconSessionDetailView(generics.RetrieveAPIView):
    """GET /api/recon/<id>/ — get a single recon session with progress."""
    serializer_class   = ReconSessionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ReconSession, self.request.user)

    def retrieve(self, request, *args, **kwargs):
        session = self.get_object()
        data    = ReconSessionSerializer(session).data

        # Include individual scan results
        scans = session.scan_results.all()
        data['scans'] = ScanResultSerializer(scans, many=True).data

        return Response(data)


# ─── Reports ───────────────────────────────────────────────────────────────────

class ReportListView(generics.ListAPIView):
    """GET /api/reports/ — list user's reports."""
    serializer_class   = ScanReportSerializer
    pagination_class   = ScanPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScanReport, self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}


class ReportDetailView(generics.RetrieveAPIView):
    """GET /api/reports/<id>/ — get report details."""
    serializer_class   = ScanReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScanReport, self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}


class GenerateReportView(APIView):
    """
    POST /api/reports/generate/
    Generate a report from a list of scan IDs.
    Body: { "scan_ids": [1, 2, 3], "organization": <optional org id> }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_ids = request.data.get('scan_ids', [])

        if not scan_ids:
            return Response(
                {'detail': 'scan_ids is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scans = org_scoped_queryset(ScanResult, request.user).filter(
            id__in=scan_ids,
            status='completed',
        )

        if not scans.exists():
            return Response(
                {'detail': 'No completed scans found for the provided IDs.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        target = scans.first().target
        org    = resolve_org(request)
        report = ScanReport.objects.create(
            user         = request.user,
            organization = org,
            target       = target,
            status       = ScanReport.Status.GENERATING,
        )
        report.scan_results.set(scans)

        generate_report.delay(scan_ids=list(scan_ids), report_id=report.id)

        logger.info("Report generation queued | report=%s user=%s scans=%s",
                    report.id, request.user.username, scan_ids)

        return Response(
            ScanReportSerializer(report, context={'request': request}).data,
            status=status.HTTP_201_CREATED
        )


class ReportDownloadView(APIView):
    """GET /api/reports/<id>/download/ — stream the PDF file or redirect to S3."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            report = org_scoped_queryset(ScanReport, request.user).get(id=pk)
        except ScanReport.DoesNotExist:
            raise Http404

        if report.status != ScanReport.Status.READY or not report.pdf_file:
            return Response(
                {'detail': 'Report is not ready yet.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        # If the file lives on remote object storage (S3/R2), redirect to the
        # pre-signed URL django-storages generates for it.
        storage = report.pdf_file.storage
        if storage.__class__.__name__ == 'S3Storage':
            return redirect(report.pdf_file.url)

        # Local filesystem — stream the file directly through Django.
        pdf_path = os.path.join(settings.MEDIA_ROOT, str(report.pdf_file))

        if not os.path.exists(pdf_path):
            return Response(
                {'detail': 'PDF file not found.'},
                status=status.HTTP_404_NOT_FOUND
            )

        filename = f"vulnsploit_report_{report.target}_{report.id}.pdf"
        response = FileResponse(
            open(pdf_path, 'rb'),
            content_type='application/pdf',
        )
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response


# ─── Organizations ─────────────────────────────────────────────────────────────

class OrganizationViewSet(viewsets.ModelViewSet):
    """CRUD for organizations the current user is a member of."""
    serializer_class   = OrganizationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return get_user_orgs(self.request.user)

    def perform_create(self, serializer):
        org = serializer.save(owner=self.request.user)
        # Creator is auto-added as the organization OWNER.
        OrganizationMember.objects.create(
            organization=org,
            user=self.request.user,
            role=OrganizationMember.Role.OWNER,
        )
        logger.info("Organization created | org=%s owner=%s", org.id, self.request.user.username)


class OrganizationMemberViewSet(viewsets.ModelViewSet):
    """Manage members of organizations the current user belongs to."""
    serializer_class   = OrganizationMemberSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return OrganizationMember.objects.filter(
            organization__in=get_user_orgs(self.request.user)
        )

    def perform_create(self, serializer):
        org = serializer.validated_data['organization']
        if not get_user_orgs(self.request.user).filter(id=org.id).exists():
            raise drf_serializers.ValidationError(
                {'organization': 'You are not a member of that organization.'}
            )
        serializer.save()
        logger.info("Member added | org=%s user=%s role=%s",
                    org.id, serializer.validated_data.get('user').username,
                    serializer.validated_data.get('role'))


# ─── Audit Logs ───────────────────────────────────────────────────────────────

class AuditLogListView(generics.ListAPIView):
    """GET /api/audit-logs/ — list audit log entries visible to the user."""
    serializer_class   = AuditLogSerializer
    pagination_class   = ScanPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_orgs = get_user_orgs(self.request.user)
        return AuditLog.objects.filter(
            dj_models.Q(organization__in=user_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )
