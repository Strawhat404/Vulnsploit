from django.db import models

class ScanResult(models.Model):
    target = models.CharField(max_length=255)
    scan_type = models.CharField(max_length=100)
    url = models.CharField(max_length=255)
    created_at = models.DateTimeField(auto_now_add=True)
    result = models.TextField()

    def __str__(self):
        return f"{self.target} - {self.scan_type} ({self.created_at})"
# Create your models here.
