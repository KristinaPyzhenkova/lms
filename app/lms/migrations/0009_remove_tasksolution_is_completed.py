# Generated by Django 4.2.2 on 2024-03-09 18:07

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0008_user_created_user_modified'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='tasksolution',
            name='is_completed',
        ),
    ]
