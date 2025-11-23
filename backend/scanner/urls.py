from django.urls import path
from .views import ScanResultListCreateView, ScanResultDetailView

urlpatterns = [
    path('scans/', ScanResultListCreateView.as_view(), name="scan-list-create"),
    path('scans/<int:pk>/',ScanResultDetailView.as_view(),name='scan_detail'),
]