from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0003_scanresult_result_json'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # Add user FK (nullable so existing rows don't break)
        migrations.AddField(
            model_name='scanresult',
            name='user',
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name='scans',
                to=settings.AUTH_USER_MODEL,
            ),
        ),
        # Add explicit status field
        migrations.AddField(
            model_name='scanresult',
            name='status',
            field=models.CharField(
                choices=[
                    ('pending',   'Pending'),
                    ('running',   'Running'),
                    ('completed', 'Completed'),
                    ('failed',    'Failed'),
                ],
                default='completed',   # existing rows are treated as completed
                max_length=20,
            ),
        ),
        # Add completed_at timestamp
        migrations.AddField(
            model_name='scanresult',
            name='completed_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
        # Add indexes for performance
        migrations.AddIndex(
            model_name='scanresult',
            index=models.Index(fields=['user', '-created_at'], name='scanner_user_created_idx'),
        ),
        migrations.AddIndex(
            model_name='scanresult',
            index=models.Index(fields=['status'], name='scanner_status_idx'),
        ),
        migrations.AddIndex(
            model_name='scanresult',
            index=models.Index(fields=['scan_type'], name='scanner_scan_type_idx'),
        ),
    ]
