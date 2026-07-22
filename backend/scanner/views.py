import logging
import os
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from django.http import FileResponse, Http404
from django.conf import settings
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator

from .models import ScanResult, ReconSession, ScanReport
from .serializers import (
    ScanResultSerializer, ReconSessionSerializer,
    ScanReportSerializer, RegisterSerializer
)
from .tasks import execute_scan, execute_full_recon, generate_report
from .validators import validate_target, validate_scan_type

logger = logging.getLogger('scanner')


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
        return ScanResult.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        target    = self.request.data.get('target', '').strip()
        scan_type = self.request.data.get('scan_type', '').strip()

        validate_target(target)
        validate_scan_type(scan_type)

        scan = serializer.save(
            user      = self.request.user,
            status    = ScanResult.Status.PENDING,
            result    = "Scan queued...",
        )
        execute_scan.delay(scan.id, target, scan_type)

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
        return ScanResult.objects.filter(user=self.request.user)


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

        session = ReconSession.objects.create(
            user   = request.user,
            target = target,
            status = ReconSession.Status.PENDING,
        )

        execute_full_recon.delay(session.id)

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
        return ReconSession.objects.filter(user=self.request.user)


class ReconSessionDetailView(generics.RetrieveAPIView):
    """GET /api/recon/<id>/ — get a single recon session with progress."""
    serializer_class   = ReconSessionSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ReconSession.objects.filter(user=self.request.user)

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
        return ScanReport.objects.filter(user=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}


class ReportDetailView(generics.RetrieveAPIView):
    """GET /api/reports/<id>/ — get report details."""
    serializer_class   = ScanReportSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return ScanReport.objects.filter(user=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}


class GenerateReportView(APIView):
    """
    POST /api/reports/generate/
    Generate a report from a list of scan IDs.
    Body: { "scan_ids": [1, 2, 3] }
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_ids = request.data.get('scan_ids', [])

        if not scan_ids:
            return Response(
                {'detail': 'scan_ids is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        scans = ScanResult.objects.filter(
            id__in=scan_ids,
            user=request.user,
            status='completed',
        )

        if not scans.exists():
            return Response(
                {'detail': 'No completed scans found for the provided IDs.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        target = scans.first().target
        report = ScanReport.objects.create(
            user   = request.user,
            target = target,
            status = ScanReport.Status.GENERATING,
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
    """GET /api/reports/<id>/download/ — stream the PDF file."""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        try:
            report = ScanReport.objects.get(id=pk, user=request.user)
        except ScanReport.DoesNotExist:
            raise Http404

        if report.status != ScanReport.Status.READY or not report.pdf_file:
            return Response(
                {'detail': 'Report is not ready yet.'},
                status=status.HTTP_400_BAD_REQUEST
            )

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
