from rest_framework import serializers
from .models import ScanResult

class ScanResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanResult
        fields = '__all__' #The Serializer includes the id the target,scan_type,output,created_at