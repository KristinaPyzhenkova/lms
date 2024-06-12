# Generated by Django 4.2.2 on 2024-05-18 13:54

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0018_emailsmtp_id_inbox_alter_mailbox_provider'),
    ]

    operations = [
        migrations.AddField(
            model_name='emailsmtp',
            name='is_answer',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='emailsmtp',
            name='is_read',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='emailsmtp',
            name='reading_time',
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='emailsmtp',
            name='template',
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='emailsmtp', to='lms.template'),
        ),
    ]