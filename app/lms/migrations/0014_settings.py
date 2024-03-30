# Generated by Django 4.2.2 on 2024-03-21 16:53

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0013_alter_usercourse_course'),
    ]

    operations = [
        migrations.CreateModel(
            name='Settings',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='Дата и время изменения')),
                ('name', models.CharField(blank=True, max_length=100, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('is_flag', models.BooleanField(default=False)),
                ('num', models.IntegerField(default=0)),
                ('float_field', models.FloatField(default=0)),
                ('content', models.JSONField(blank=True, null=True)),
            ],
            options={
                'verbose_name': 'Настройки',
                'verbose_name_plural': 'Настройки',
                'ordering': ['-id'],
            },
        ),
    ]
