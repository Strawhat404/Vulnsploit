from django.shortcuts import render
from rest_framework import generics
from .models import ScanResult
from .serializers import ScanResultSerializer
# Create your views here.

#List all scan results OR create a new scan result

class ScanResultListCreateView(generics.ListCreateAPIView):
    queryset = ScanResult.objects.all().order_by('-created_at')
    serializer_class = ScanResultSerializer


#retrieve a single scan result by ID

class ScanResultDetailView(generics.RetrieveAPIView):
    queryset = ScanResult.objects.all()
    serializer_class = ScanResultSerializer