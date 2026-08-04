import os   
from celery import Celery 

os.environ.setdefault('DJANGO_SETTINGS_MODULE','Vulnsploit.settings')

app = Celery('Vulnsploit')

app.config_from_object('django.conf:settings',namespace='CELERY')

app.autodiscover_tasks()

# Use django-celery-beat's DatabaseScheduler so scheduled scans stored in the
# database (and CrontabSchedule/PeriodicTask rows created from ScheduledScan)
# actually drive the Celery Beat dispatcher.
app.conf.beat_scheduler = 'django_celery_beat.schedulers.DatabaseScheduler'