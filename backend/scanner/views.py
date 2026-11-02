import logging
import os
from rest_framework import generics, status, viewsets
from rest_framework.decorators import action
from rest_framework import serializers as drf_serializers
from rest_framework.exceptions import PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.shortcuts import get_object_or_404, redirect
from django.http import FileResponse, Http404
from django.conf import settings
from django.contrib.auth import update_session_auth_hash
from django.db import IntegrityError, models as dj_models, transaction
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import (
    UserProfile, APIKey, Target, ScheduledScan, ScanResult, ReconSession, ScanReport,
    Organization, OrganizationMember, AuditLog, WebhookEndpoint, FindingStatus,
)
from .serializers import (
    TargetSerializer, ScanResultSerializer, ReconSessionSerializer,
    ScanReportSerializer, RegisterSerializer, ProfileSerializer,
    ChangePasswordSerializer, CreateAPIKeySerializer, APIKeySerializer,
    ScheduledScanSerializer, OrganizationSerializer, OrganizationMemberSerializer,
    AuditLogSerializer, WebhookEndpointSerializer, FindingStatusSerializer,
)
from .tasks import execute_scan, execute_full_recon, generate_report
from .validators import validate_target, validate_scan_type, guess_target_type
from .authorization import authorize_target
from .permissions import OrgRoleMixin, ROLE_RANK, require_role, role_in_org
from .verification import verify_target, mark_verified

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


def resolve_org(request, min_role=None):
    """
    Resolve an optional organization from request.data. Returns an
    Organization instance if a valid org id is provided AND the user is a
    member, else None (private to user).
    Raises a ValidationError if an org is provided but the user is not a member,
    and a 403 if ``min_role`` is given and the user's role in it is lower.
    """
    org_id = request.data.get('organization')
    if not org_id:
        return None
    user_orgs = get_user_orgs(request.user)
    try:
        org = user_orgs.get(id=org_id)
    except (Organization.DoesNotExist, ValueError, TypeError):
        raise drf_serializers.ValidationError(
            {'organization': 'Not a member of that organization.'}
        )
    if min_role:
        require_role(request.user, org, min_role)
    return org


# ─── JWT with httpOnly cookie ───────────────────────────────────────────────────

from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.exceptions import InvalidToken, TokenError
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
        # The refresh token normally arrives in the httpOnly cookie; the SPA
        # POSTs an empty JSON body. Build the serializer input ourselves
        # rather than mutating request.data, which is a plain dict for JSON
        # requests and an immutable QueryDict for form posts.
        data = {}
        refresh = request.data.get('refresh') or request.COOKIES.get('refresh_token')
        if refresh:
            data['refresh'] = refresh

        serializer = self.get_serializer(data=data)
        try:
            serializer.is_valid(raise_exception=True)
        except TokenError as exc:
            raise InvalidToken(exc.args[0])
        return Response(serializer.validated_data, status=status.HTTP_200_OK)


# ─── User Stats ─────────────────────────────────────────────────────────────────

class UserStatsView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = org_scoped_queryset(ScanResult, request.user)
        reports = org_scoped_queryset(ScanReport, request.user)

        # Calculate posture score from the most recent report
        posture_score = None
        posture_grade = None
        latest_report = reports.filter(status='ready').order_by('-generated_at').first()
        if latest_report and latest_report.severity_counts:
            from .posture import calculate_posture_score, posture_grade as _pg
            posture_score = calculate_posture_score(
                latest_report.severity_counts,
                len(latest_report.findings_json or []),
            )
            posture_grade = _pg(posture_score)

        return Response({
            'total': scans.count(),
            'completed': scans.filter(status='completed').count(),
            'running': scans.filter(status__in=['running', 'pending']).count(),
            'failed': scans.filter(status='failed').count(),
            'recon_sessions': org_scoped_queryset(ReconSession, request.user).count(),
            'reports': reports.count(),
            'posture_score': posture_score,
            'posture_grade': posture_grade,
        })


# ─── Targets ───────────────────────────────────────────────────────────────────

class TargetViewSet(OrgRoleMixin, viewsets.ModelViewSet):
    write_role         = 'admin'
    serializer_class   = TargetSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(Target, self.request.user)

    def perform_create(self, serializer):
        serializer.save(
            user=self.request.user,
            organization=resolve_org(self.request, min_role=self.write_role),
        )

    def perform_update(self, serializer):
        instance  = serializer.instance
        old_value = instance.value
        target = serializer.save(user=instance.user, organization=instance.organization)
        if target.value != old_value:
            # Proof for the old value says nothing about the new one.
            target.reset_verification()
            target.save(update_fields=[
                'verification_token', 'verification_method',
                'verified_at', 'authorization_confirmed_at', 'expiry_notice_sent',
            ])

    BULK_ADD_MAX = 100
    BULK_VERIFY_MAX = 20

    @action(detail=False, methods=['post'], url_path='bulk')
    def bulk(self, request):
        """
        POST /api/targets/bulk/
        Body: {"values": ["example.com", "10.0.0.1", ...], "organization": <optional id>}

        Adds many targets at once. Each line is handled on its own: a bad line
        is reported and skipped, never failing the rest. Nothing is contacted.
        """
        values = request.data.get('values')
        if not isinstance(values, list):
            return Response({'detail': "'values' must be a list of targets."},
                            status=status.HTTP_400_BAD_REQUEST)
        if len(values) > self.BULK_ADD_MAX:
            return Response({'detail': f'At most {self.BULK_ADD_MAX} targets per request.'},
                            status=status.HTTP_400_BAD_REQUEST)

        org = resolve_org(request, min_role=self.write_role)
        owned = set(org_scoped_queryset(Target, request.user)
                    .filter(organization=org).values_list('value', flat=True)) \
            if org else set(Target.objects.filter(user=request.user, organization__isnull=True)
                            .values_list('value', flat=True))
        owned_lower = {v.lower() for v in owned}

        results, seen = [], set()
        counts = {'created': 0, 'existing': 0, 'invalid': 0}
        for raw in values:
            if not isinstance(raw, str):
                results.append({'value': str(raw)[:80], 'status': 'invalid', 'detail': 'Must be text.'})
                counts['invalid'] += 1
                continue
            value = raw.strip()
            if not value:
                continue
            key = value.lower()
            if key in seen:
                continue
            seen.add(key)

            try:
                clean = validate_target(value, resolve=False)
            except drf_serializers.ValidationError as exc:
                detail = exc.detail
                detail = next(iter(detail.values())) if isinstance(detail, dict) else detail
                detail = detail[0] if isinstance(detail, list) else detail
                results.append({'value': value, 'status': 'invalid', 'detail': str(detail)})
                counts['invalid'] += 1
                continue

            if clean.lower() in owned_lower:
                existing = Target.objects.filter(user=request.user, organization=org, value__iexact=clean).first()
                results.append({'value': clean, 'status': 'exists', 'id': existing.id if existing else None})
                counts['existing'] += 1
                continue

            target = Target.objects.create(
                user=request.user, organization=org, name=clean[:100], value=clean,
                target_type=guess_target_type(clean),
            )
            results.append({'value': clean, 'status': 'created', 'id': target.id})
            counts['created'] += 1

        logger.info("Bulk targets | user=%s created=%d existing=%d invalid=%d",
                    request.user.username, counts['created'], counts['existing'], counts['invalid'])
        return Response({**counts, 'results': results})

    @action(detail=False, methods=['post'], url_path='verify-bulk')
    @method_decorator(ratelimit(key='user', rate='10/h', method='POST', block=True))
    def verify_bulk(self, request):
        """
        POST /api/targets/verify-bulk/
        Body: {"ids": [1, 2, ...], "method": "dns" | "http", "confirm_authorization": true}

        Runs the chosen check for each target and reports every outcome.
        """
        if request.data.get('confirm_authorization') is not True:
            return Response(
                {'detail': 'You must confirm you are authorized to test these targets.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        method = request.data.get('method')
        if method not in ('dns', 'http'):
            return Response({'detail': "method must be 'dns' or 'http'."},
                            status=status.HTTP_400_BAD_REQUEST)

        ids = request.data.get('ids')
        if (not isinstance(ids, list) or not ids
                or not all(isinstance(i, int) and not isinstance(i, bool) for i in ids)):
            return Response({'detail': "'ids' must be a non-empty list of integers."},
                            status=status.HTTP_400_BAD_REQUEST)
        if len(ids) > self.BULK_VERIFY_MAX:
            return Response({'detail': f'At most {self.BULK_VERIFY_MAX} targets per request.'},
                            status=status.HTTP_400_BAD_REQUEST)

        targets = {t.id: t for t in self.get_queryset().filter(id__in=ids)}
        results, ok_count = [], 0
        for tid in dict.fromkeys(ids):
            target = targets.get(tid)
            if target is None:
                results.append({'id': tid, 'value': None, 'verified': False, 'detail': 'Target not found.'})
                continue
            try:
                require_role(request.user, target.organization_id, self.write_role)
            except PermissionDenied as exc:
                results.append({'id': tid, 'value': target.value, 'verified': False,
                                'detail': str(exc.detail)})
                continue
            ok, message = verify_target(target, method)
            if ok:
                mark_verified(target, method)
                ok_count += 1
            results.append({'id': tid, 'value': target.value, 'verified': ok, 'detail': message})

        logger.info("Bulk verify | user=%s method=%s ok=%d total=%d",
                    request.user.username, method, ok_count, len(results))
        return Response({'verified': ok_count, 'failed': len(results) - ok_count, 'results': results})

    @action(detail=True, methods=['post'], url_path='verify')
    @method_decorator(ratelimit(key='user', rate='30/h', method='POST', block=True))
    def verify(self, request, pk=None):
        """
        POST /api/targets/<id>/verify/
        Body: {"method": "dns" | "http", "confirm_authorization": true}
        """
        target = self.get_object()

        if request.data.get('confirm_authorization') is not True:
            return Response(
                {'detail': 'You must confirm you are authorized to test this target.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        method = request.data.get('method')
        if method not in ('dns', 'http'):
            return Response(
                {'detail': "method must be 'dns' or 'http'."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        ok, message = verify_target(target, method)
        if not ok:
            return Response({'detail': message}, status=status.HTTP_400_BAD_REQUEST)

        mark_verified(target, method)
        logger.info("Target verified | target=%s method=%s user=%s",
                    target.id, method, request.user.username)
        return Response(self.get_serializer(target).data)


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
        require_role(request.user, scan.organization_id, 'analyst')
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
        require_role(request.user, session.organization_id, 'analyst')
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

class ScheduledScanListCreateView(OrgRoleMixin, generics.ListCreateAPIView):
    write_role         = 'admin'
    serializer_class   = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScheduledScan, self.request.user)

    def perform_create(self, serializer):
        org = resolve_org(self.request, min_role=self.write_role)
        authorize_target(self.request.user, org, serializer.validated_data['target'])
        instance = serializer.save(user=self.request.user, organization=org)
        _create_beat_schedule(serializer, org, self.request.user)


class ScheduledScanDetailView(OrgRoleMixin, generics.RetrieveUpdateDestroyAPIView):
    write_role         = 'admin'
    serializer_class   = ScheduledScanSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return org_scoped_queryset(ScheduledScan, self.request.user)

    def perform_destroy(self, instance):
        _remove_beat_schedule(instance)
        instance.delete()

    def perform_update(self, serializer):
        current = serializer.instance
        target = serializer.validated_data.get('target', current.target)
        authorize_target(self.request.user, current.organization, target)
        instance = serializer.save(user=current.user, organization=current.organization)
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
        org = resolve_org(self.request, min_role='analyst')
        authorize_target(self.request.user, org, target)

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

        org = resolve_org(request, min_role='analyst')
        authorize_target(request.user, org, target)

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

        if (
            not isinstance(scan_ids, list)
            or not all(isinstance(i, int) and not isinstance(i, bool) for i in scan_ids)
        ):
            return Response(
                {'detail': 'scan_ids must be a list of integers.'},
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

        # Only the scans this user is allowed to see go any further.
        allowed_ids = list(scans.values_list('id', flat=True))
        target = scans.first().target
        org    = resolve_org(request, min_role='analyst')
        report = ScanReport.objects.create(
            user         = request.user,
            organization = org,
            target       = target,
            status       = ScanReport.Status.GENERATING,
        )
        report.scan_results.set(scans)

        generate_report.delay(scan_ids=allowed_ids, report_id=report.id)

        logger.info("Report generation queued | report=%s user=%s scans=%s",
                    report.id, request.user.username, allowed_ids)

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

    def perform_update(self, serializer):
        require_role(self.request.user, serializer.instance, 'owner')
        serializer.save()

    def perform_destroy(self, instance):
        require_role(self.request.user, instance, 'owner')
        instance.delete()


def _owner_count(org_id):
    return OrganizationMember.objects.filter(
        organization_id=org_id, role=OrganizationMember.Role.OWNER,
    ).count()


class OrganizationMemberViewSet(viewsets.ModelViewSet):
    """
    Manage members of organizations the current user belongs to.

    Admins manage analysts and viewers; only owners create, change or remove
    admins and owners. Nobody changes their own role, and an organization
    always keeps at least one owner.
    """
    serializer_class   = OrganizationMemberSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return OrganizationMember.objects.filter(
            organization__in=get_user_orgs(self.request.user)
        )

    @staticmethod
    def _need_owner_for(role):
        return role in (OrganizationMember.Role.OWNER, OrganizationMember.Role.ADMIN)

    def _actor_role(self, org_id, minimum='admin'):
        """Caller's role in the org; 403 if below ``minimum``."""
        require_role(self.request.user, org_id, minimum)
        return role_in_org(self.request.user, org_id)

    def perform_create(self, serializer):
        org = serializer.validated_data['organization']
        if role_in_org(self.request.user, org) is None:
            raise drf_serializers.ValidationError(
                {'organization': 'You are not a member of that organization.'}
            )
        actor = self._actor_role(org)
        new_role = serializer.validated_data.get('role', OrganizationMember.Role.VIEWER)
        if self._need_owner_for(new_role) and actor != 'owner':
            raise PermissionDenied('Only an owner can add admins or owners.')
        serializer.save()
        logger.info("Member added | org=%s user=%s role=%s",
                    org.id, serializer.validated_data.get('user').username, new_role)

    def perform_update(self, serializer):
        member = serializer.instance
        actor = self._actor_role(member.organization_id)
        if member.user_id == self.request.user.id:
            raise PermissionDenied('You cannot change your own role.')

        new_role = serializer.validated_data.get('role', member.role)
        if actor != 'owner' and (self._need_owner_for(member.role) or self._need_owner_for(new_role)):
            raise PermissionDenied('Only an owner can change admins or owners, or grant those roles.')
        if (member.role == OrganizationMember.Role.OWNER
                and new_role != OrganizationMember.Role.OWNER
                and _owner_count(member.organization_id) <= 1):
            raise PermissionDenied('An organization must keep at least one owner.')

        # Membership identity is fixed; only the role may change.
        serializer.save(organization=member.organization, user=member.user)

    def perform_destroy(self, member):
        leaving = member.user_id == self.request.user.id
        if not leaving:
            actor = self._actor_role(member.organization_id)
            if actor != 'owner' and self._need_owner_for(member.role):
                raise PermissionDenied('Only an owner can remove admins or owners.')
        elif role_in_org(self.request.user, member.organization_id) is None:
            raise PermissionDenied('Not a member of this organization.')

        if (member.role == OrganizationMember.Role.OWNER
                and _owner_count(member.organization_id) <= 1):
            raise PermissionDenied('An organization must keep at least one owner.')
        member.delete()


# ─── Audit Logs ───────────────────────────────────────────────────────────────

class AuditLogListView(generics.ListAPIView):
    """
    GET /api/audit-logs/ — the user's own private entries, plus the full log
    of every organization where they are an admin or owner.
    """
    serializer_class   = AuditLogSerializer
    pagination_class   = ScanPagination
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        managed_orgs = Organization.objects.filter(
            memberships__user=self.request.user,
            memberships__role__in=[OrganizationMember.Role.ADMIN, OrganizationMember.Role.OWNER],
        )
        return AuditLog.objects.filter(
            dj_models.Q(organization__in=managed_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )


# ─── Report Comparison ────────────────────────────────────────────────────────

class ReportCompareView(APIView):
    """
    GET /api/reports/compare/?report_a=<id>&report_b=<id>
    Returns a diff of the two reports' findings.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        a_id = request.query_params.get('report_a')
        b_id = request.query_params.get('report_b')

        if not a_id or not b_id:
            return Response(
                {'detail': 'Both report_a and report_b query params are required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = org_scoped_queryset(ScanReport, request.user)
        try:
            report_a = qs.get(id=int(a_id))
            report_b = qs.get(id=int(b_id))
        except (ScanReport.DoesNotExist, ValueError):
            return Response(
                {'detail': 'One or both reports not found.'},
                status=status.HTTP_404_NOT_FOUND,
            )

        from .diff import compare_reports
        diff = compare_reports(
            report_a.findings_json or [],
            report_b.findings_json or [],
        )

        # Add posture scores for context
        from .posture import calculate_posture_score, posture_grade, posture_label
        for label, report in [('report_a', report_a), ('report_b', report_b)]:
            if report.severity_counts:
                score = calculate_posture_score(
                    report.severity_counts,
                    len(report.findings_json or []),
                )
                diff[f'{label}_posture_score']  = score
                diff[f'{label}_posture_grade']  = posture_grade(score)
                diff[f'{label}_posture_label']  = posture_label(score)

        return Response(diff)


class ReportExportView(APIView):
    """
    GET /api/reports/<id>/export/?format=sarif|json
    Exports findings as SARIF 2.1.0 or plain JSON.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        qs = org_scoped_queryset(ScanReport, request.user)
        try:
            report = qs.get(id=pk)
        except ScanReport.DoesNotExist:
            raise Http404

        if report.status != ScanReport.Status.READY:
            return Response(
                {'detail': 'Report is not ready yet.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        fmt = request.query_params.get('format', 'json').lower()
        findings = report.findings_json or []

        if fmt == 'sarif':
            from .exports import findings_to_sarif
            return Response(findings_to_sarif(findings, report.target))

        elif fmt == 'json':
            from .exports import findings_to_json
            from .posture import calculate_posture_score
            score = calculate_posture_score(
                report.severity_counts or {},
                len(findings),
            )
            report_data = {
                'id':              report.id,
                'target':          report.target,
                'risk_level':      report.risk_level,
                'posture_score':   score,
                'severity_counts': report.severity_counts,
                'total_findings':  len(findings),
                'dedup_stats':     None,
                'compliance_summary': None,
                'generated_at':    report.generated_at,
            }
            return Response(findings_to_json(findings, report_data))

        return Response(
            {'detail': 'Unsupported format. Use ?format=sarif or ?format=json'},
            status=status.HTTP_400_BAD_REQUEST,
        )


# ─── Webhook Endpoints ─────────────────────────────────────────────────────────

class WebhookEndpointViewSet(OrgRoleMixin, viewsets.ModelViewSet):
    write_role         = 'admin'
    """CRUD for webhook endpoints (Slack/Teams/Discord/alerting)."""
    serializer_class   = WebhookEndpointSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        user_orgs = get_user_orgs(self.request.user)
        return WebhookEndpoint.objects.filter(
            dj_models.Q(organization__in=user_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )

    def perform_create(self, serializer):
        import secrets as _secrets
        # Auto-generate HMAC secret if not provided
        if not serializer.validated_data.get('secret'):
            serializer.validated_data['secret'] = _secrets.token_hex(32)
        serializer.save(
            user=self.request.user,
            organization=resolve_org(self.request, min_role=self.write_role),
        )

    def perform_update(self, serializer):
        instance = serializer.instance
        serializer.save(user=instance.user, organization=instance.organization)


# ─── Finding Status / False Positive Suppression ──────────────────────────────

class FindingStatusViewSet(OrgRoleMixin, viewsets.ModelViewSet):
    write_role         = 'analyst'
    """
    CRUD for finding triage decisions (false positive, accepted risk,
    remediated). Suppressions are scoped to a target and persist across
    scans — suppressed findings are tagged but not removed from reports,
    and false positives are excluded from severity counts / posture score.
    """
    serializer_class   = FindingStatusSerializer
    permission_classes = [IsAuthenticated]
    pagination_class   = ScanPagination
    filterset_fields   = ['target', 'decision']

    def get_queryset(self):
        user_orgs = get_user_orgs(self.request.user)
        qs = FindingStatus.objects.filter(
            dj_models.Q(organization__in=user_orgs) |
            dj_models.Q(organization__isnull=True, user=self.request.user)
        )
        # Optional filter by target
        target = self.request.query_params.get('target')
        if target:
            qs = qs.filter(target=target)
        return qs

    def _save_unique(self, serializer, **owner):
        try:
            with transaction.atomic():
                serializer.save(**owner)
        except IntegrityError:
            raise drf_serializers.ValidationError(
                {'fingerprint': 'A decision already exists for this finding on this target.'}
            )

    def perform_create(self, serializer):
        self._save_unique(
            serializer, user=self.request.user,
            organization=resolve_org(self.request, min_role=self.write_role),
        )

    def perform_update(self, serializer):
        # Ownership is fixed at creation; a PATCH must not move a decision
        # into another organization.
        instance = serializer.instance
        self._save_unique(serializer, user=instance.user, organization=instance.organization)
