from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import (
    RegisterView,
    ScanResultListCreateView, ScanResultDetailView,
    FullReconView, ReconSessionListView, ReconSessionDetailView,
    ReportListView, ReportDetailView, GenerateReportView, ReportDownloadView,
    UserStatsView, TargetViewSet, ProfileView, ChangePasswordView,
    APIKeyListView, APIKeyDetailView,
    ScheduledScanListCreateView, ScheduledScanDetailView,
    CancelScanView, CancelReconView,
    OrganizationViewSet, OrganizationMemberViewSet, AuditLogListView,
)

router = DefaultRouter()
router.register(r'targets', TargetViewSet, basename='target')
router.register(r'organizations', OrganizationViewSet, basename='organization')
router.register(r'organization-members', OrganizationMemberViewSet, basename='organization-member')

urlpatterns = [
    path('', include(router.urls)),

    # Stats
    path('stats/',                       UserStatsView.as_view(),             name='user-stats'),

    # Profile
    path('profile/',                     ProfileView.as_view(),               name='user-profile'),
    path('change-password/',             ChangePasswordView.as_view(),        name='change-password'),

    # API Keys
    path('api-keys/',                    APIKeyListView.as_view(),            name='api-key-list'),
    path('api-keys/<int:pk>/',           APIKeyDetailView.as_view(),          name='api-key-detail'),

    # Scheduled Scans
    path('scheduled-scans/',             ScheduledScanListCreateView.as_view(), name='scheduled-scan-list'),
    path('scheduled-scans/<int:pk>/',    ScheduledScanDetailView.as_view(),     name='scheduled-scan-detail'),

    # Audit logs
    path('audit-logs/',                  AuditLogListView.as_view(),          name='audit-log-list'),

    # Auth
    path('register/',                   RegisterView.as_view(),              name='register'),

    # Individual scans
    path('scans/',                       ScanResultListCreateView.as_view(),  name='scan-list-create'),
    path('scans/<int:pk>/',              ScanResultDetailView.as_view(),      name='scan-detail'),
    path('scans/<int:pk>/cancel/',       CancelScanView.as_view(),            name='scan-cancel'),

    # Full recon sessions
    path('recon/',                       FullReconView.as_view(),             name='recon-create'),
    path('recon/list/',                  ReconSessionListView.as_view(),      name='recon-list'),
    path('recon/<int:pk>/',              ReconSessionDetailView.as_view(),    name='recon-detail'),
    path('recon/<int:pk>/cancel/',       CancelReconView.as_view(),           name='recon-cancel'),

    # Reports
    path('reports/',                     ReportListView.as_view(),            name='report-list'),
    path('reports/<int:pk>/',            ReportDetailView.as_view(),          name='report-detail'),
    path('reports/generate/',            GenerateReportView.as_view(),        name='report-generate'),
    path('reports/<int:pk>/download/',   ReportDownloadView.as_view(),        name='report-download'),
]
