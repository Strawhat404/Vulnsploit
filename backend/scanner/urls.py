from django.urls import path
from .views import (
    RegisterView,
    ScanResultListCreateView, ScanResultDetailView,
    FullReconView, ReconSessionListView, ReconSessionDetailView,
    ReportListView, ReportDetailView, GenerateReportView, ReportDownloadView,
)

urlpatterns = [
    # Auth
    path('register/',                   RegisterView.as_view(),              name='register'),

    # Individual scans
    path('scans/',                       ScanResultListCreateView.as_view(),  name='scan-list-create'),
    path('scans/<int:pk>/',              ScanResultDetailView.as_view(),      name='scan-detail'),

    # Full recon sessions
    path('recon/',                       FullReconView.as_view(),             name='recon-create'),
    path('recon/list/',                  ReconSessionListView.as_view(),      name='recon-list'),
    path('recon/<int:pk>/',              ReconSessionDetailView.as_view(),    name='recon-detail'),

    # Reports
    path('reports/',                     ReportListView.as_view(),            name='report-list'),
    path('reports/<int:pk>/',            ReportDetailView.as_view(),          name='report-detail'),
    path('reports/generate/',            GenerateReportView.as_view(),        name='report-generate'),
    path('reports/<int:pk>/download/',   ReportDownloadView.as_view(),        name='report-download'),
]
