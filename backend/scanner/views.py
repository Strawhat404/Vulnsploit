from django.shortcuts import render
from rest_framework import generics
from .models import ScanResult
from .serializers import ScanResultSerializer
from .utils import run_nmap

class ScanResultListCreateView(generics.ListCreateAPIView):
    queryset = ScanResult.objects.all().order_by('-created_at')
    serializer_class = ScanResultSerializer

    def perform_create(self, serializer):
        target = self.request.data.get('target')
        scan_type = self.request.data.get("scan_type")

        # Call our utility function that executes Nmap inside Docker
        output = run_nmap(target, scan_type)

        serializer.save(result=output)

class ScanResultDetailView(generics.RetrieveAPIView):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer
