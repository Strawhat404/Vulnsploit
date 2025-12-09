from celery import shared_task
from .utils import run_scan
from .models import ScanResult

@shared_task

def execute_scan(scan_id,target,scan_type):

    try:
        scan = ScanResult.objects.get(id=scan_id)

        #Run the scan (now returns tuple)
        result_text,result_json = run_scan(scan.target, scan.scan_type)

        scan.result = result_text
        scan.result_json = result_json

        scan.save()
        return f"Scan {scan_id} completed successfully"

    except ScanResult.DoesNotExist:
        return f"Scan {scan_id} not found"


    except Exception as e:
        try:
            scan = ScanResult.objects.get(id=scan_id) 
            scan.result = f"Error: {str(e)}"
            scan.save()
        except:
            pass #if we san fetch the scan , we can't save the errror
        return f"Error in scan {scan_id}: {str(e)}"
            
        