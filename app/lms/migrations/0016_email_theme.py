# Generated by Django 4.2.2 on 2024-04-01 18:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0015_email'),
    ]

    operations = [
        migrations.AddField(
            model_name='email',
            name='theme',
            field=models.CharField(default='theme', max_length=25, verbose_name='theme'),
            preserve_default=False,
        ),
    ]
