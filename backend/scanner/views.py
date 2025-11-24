from django.shortcuts import render
from rest_framework import generics
from .models import ScanResult
from .serializers import ScanResultSerializer
from .utils import run_nmap

# Create your views here.

#List all scan results OR create a new scan result

class ScanResultListCreateView(generics.ListCreateAPIView):
    queryset = ScanResult.objects.all().order_by('-created_at')
    serializer_class = ScanResultSerializer

    def perform_create(self, serializer):
        target = self.request.data.get('target')
        scan_type = self.request.data.get("scan_type")

        if scan_type == "nmap":
            output = run_nmap(target)
        else:
            output = "Unknown scan type."

        serializer.save(result=output)


#retrieve a single scan result by ID

class ScanResultDetailView(generics.RetrieveAPIView):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer