import os   
from celery import celery 

os.environ.setdefault('Django_SETTINGS_MODULE','vulnsploit.settings')

app = Celery('Vulnsploit')

app.config_from_object('django.conf:settings',namespace='CELERY')

app.autodiscover_tasks()