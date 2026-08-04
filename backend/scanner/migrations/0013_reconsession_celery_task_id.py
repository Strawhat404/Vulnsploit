from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0012_scanresult_celery_task_id'),
    ]

    operations = [
        migrations.AddField(
            model_name='reconsession',
            name='celery_task_id',
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
