from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('scanner', '0010_apikey'),
    ]

    operations = [
        migrations.CreateModel(
            name='ScheduledScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('target', models.CharField(max_length=255)),
                ('scan_type', models.CharField(choices=[('quick', 'Quick Scan'), ('full', 'Full Scan'), ('nikto', 'Nikto'), ('gobuster', 'Gobuster'), ('nuclei', 'Nuclei'), ('whatweb', 'WhatWeb'), ('subfinder', 'Subfinder'), ('wpscan', 'WPScan'), ('testssl', 'TestSSL'), ('headers', 'Headers Check'), ('sqlmap', 'SQLMap'), ('full_recon', 'Full Recon')], max_length=100)),
                ('cron', models.CharField(help_text='Cron expression (e.g. 0 2 * * 1)', max_length=100)),
                ('is_active', models.BooleanField(default=True)),
                ('last_run_at', models.DateTimeField(blank=True, null=True)),
                ('next_run_at', models.DateTimeField(blank=True, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='scheduled_scans', to='auth.user')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
