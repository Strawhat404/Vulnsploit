from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0011_scheduledscan'),
    ]

    operations = [
        migrations.AddField(
            model_name='scanresult',
            name='celery_task_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
