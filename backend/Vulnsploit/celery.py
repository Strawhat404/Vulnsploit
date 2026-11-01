import os   
from celery import Celery
from celery.schedules import crontab

os.environ.setdefault('DJANGO_SETTINGS_MODULE','Vulnsploit.settings')

app = Celery('Vulnsploit')

app.config_from_object('django.conf:settings',namespace='CELERY')

app.autodiscover_tasks()

# Use django-celery-beat's DatabaseScheduler so scheduled scans stored in the
# database (and CrontabSchedule/PeriodicTask rows created from ScheduledScan)
# actually drive the Celery Beat dispatcher.
app.conf.beat_scheduler = 'django_celery_beat.schedulers.DatabaseScheduler'

# Static periodic tasks. DatabaseScheduler copies these into the database on
# startup, alongside the per-user ScheduledScan entries.
app.conf.beat_schedule = {
    'warn-expiring-verifications': {
        'task': 'scanner.tasks.warn_expiring_verifications',
        'schedule': crontab(hour=8, minute=0),
    },
}
