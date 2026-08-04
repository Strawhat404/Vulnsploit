from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
        ('scanner', '0007_rename_session_scanresult_recon_session_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='Target',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('value', models.CharField(max_length=255)),
                ('target_type', models.CharField(choices=[('domain', 'Domain'), ('ip', 'IP Address'), ('url', 'URL'), ('cidr', 'CIDR Range')], max_length=20)),
                ('tags', models.JSONField(default=list)),
                ('notes', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('last_scanned_at', models.DateTimeField(blank=True, null=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='targets', to='auth.user')),
            ],
            options={
                'ordering': ['-created_at'],
                'unique_together': {('user', 'value')},
            },
        ),
    ]
