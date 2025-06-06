# Generated by Django 4.2.21 on 2025-06-05 16:50

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('watermark', '0006_profile_two_factor_enabled'),
    ]

    operations = [
        migrations.CreateModel(
            name='DecryptedDocument',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='Nom donné au PDF déchiffré', max_length=255)),
                ('file', models.FileField(upload_to='decrypted_pdfs/')),
                ('decrypted_at', models.DateTimeField(auto_now_add=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
