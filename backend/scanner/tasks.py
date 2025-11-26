from celery import shared_task
from .utils import run_scan
from .models import ScanResult

@shared_task

def execute_scan(scan_id,target,scan_type):

    try:

        output = run_scan(target,scan_type)

        scan = ScanResult.objects.get(id=scan_id)
        
        scan.result = output
        scan.save()

        return f"Scan {scan_id} completed successfully"

    except ScanResult.DoesNotExist:
        return f"Scan {scan_id} not found"
    except Exception as e:
        return f"Error in scan{scan_id}: {str(e)}"