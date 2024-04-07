# Generated by Django 4.2.2 on 2024-04-06 19:40

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('lms', '0016_email_theme'),
    ]

    operations = [
        migrations.CreateModel(
            name='Template',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('text', models.TextField()),
            ],
        ),
        migrations.AlterField(
            model_name='user',
            name='role',
            field=models.CharField(choices=[('Студент', 'Студент'), ('Наставник', 'Наставник'), ('Админ', 'Админ')], default='Студент', max_length=50, verbose_name='Роль'),
        ),
        migrations.CreateModel(
            name='Mailbox',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('provider', models.CharField(choices=[('google', 'Google'), ('webmail', 'webmail')], max_length=20)),
                ('email', models.EmailField(max_length=254)),
                ('password', models.CharField(max_length=255)),
                ('courses', models.ManyToManyField(related_name='mailboxes', to='lms.course')),
            ],
        ),
        migrations.CreateModel(
            name='EmailSMTP',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True)),
                ('modified', models.DateTimeField(auto_now=True, verbose_name='Дата и время изменения')),
                ('sender', models.EmailField(max_length=254)),
                ('recipient', models.EmailField(max_length=254)),
                ('subject', models.CharField(max_length=255)),
                ('body', models.TextField()),
                ('sent_at', models.DateTimeField(auto_now_add=True)),
                ('mailbox', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='emailsmtp', to='lms.mailbox')),
            ],
            options={
                'abstract': False,
            },
        ),
    ]
