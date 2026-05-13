from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('scanner', '0005_alter_scanresult_options_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        # ── ReconSession ──────────────────────────────────────────────────────
        migrations.CreateModel(
            name='ReconSession',
            fields=[
                ('id',           models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target',       models.CharField(max_length=255)),
                ('status',       models.CharField(
                    choices=[('pending','Pending'),('running','Running'),
                             ('completed','Completed'),('failed','Failed')],
                    default='pending', max_length=20)),
                ('created_at',   models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('tools_config', models.JSONField(blank=True, default=list)),
                ('user',         models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='sessions',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-created_at']},
        ),

        # ── ScanReport ────────────────────────────────────────────────────────
        migrations.CreateModel(
            name='ScanReport',
            fields=[
                ('id',             models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target',         models.CharField(max_length=255)),
                ('status',         models.CharField(
                    choices=[('generating','Generating'),('ready','Ready'),('failed','Failed')],
                    default='generating', max_length=20)),
                ('created_at',     models.DateTimeField(auto_now_add=True)),
                ('findings_json',  models.JSONField(blank=True, default=dict)),
                ('scan_ids',       models.JSONField(blank=True, default=list)),
                ('critical_count', models.IntegerField(default=0)),
                ('high_count',     models.IntegerField(default=0)),
                ('medium_count',   models.IntegerField(default=0)),
                ('low_count',      models.IntegerField(default=0)),
                ('info_count',     models.IntegerField(default=0)),
                ('pdf_file',       models.FileField(blank=True, null=True, upload_to='reports/')),
                ('session',        models.OneToOneField(
                    blank=True, null=True,
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='report',
                    to='scanner.reconsession',
                )),
                ('user',           models.ForeignKey(
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='reports',
                    to=settings.AUTH_USER_MODEL,
                )),
            ],
            options={'ordering': ['-created_at']},
        ),

        # ── Add session FK to ScanResult ──────────────────────────────────────
        migrations.AddField(
            model_name='scanresult',
            name='session',
            field=models.ForeignKey(
                blank=True, null=True,
                on_delete=django.db.models.deletion.SET_NULL,
                related_name='scan_results',
                to='scanner.reconsession',
            ),
        ),
    ]
