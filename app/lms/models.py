import datetime
import pprint
import re
import typing

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils import timezone
from django.utils.translation import gettext_lazy as _

from lms.validators import validate_phone_number
from lms import const


class CommonFields(models.Model):
    """Common fields across models."""

    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(
        auto_now=True,
        verbose_name='Дата и время изменения'
    )

    class Meta:
        abstract = True


class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get('is_superuser') is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self._create_user(email, password, **extra_fields)


class Course(CommonFields):
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    description = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Курс'
        verbose_name_plural = 'Курсы'

    def __str__(self):
        return f'{self.name} - {self.id}'


class User(AbstractUser, CommonFields):
    STUDENT = 'Студент'
    MENTOR = 'Наставник'
    ADMIN = 'Админ'
    ROLE = (
        (STUDENT, STUDENT),
        (MENTOR, MENTOR),
        (ADMIN, ADMIN),
    )
    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(
        _('email'),
        max_length=254,
        unique=True,
        error_messages={
            'unique': _("A user with that email already exists."),
        },
    )
    email_personal = models.EmailField(
        _('email_personal'),
        max_length=254,
        unique=True,
        error_messages={
            'unique': _("A user with that email already exists."),
        },
    )
    role = models.CharField(
        max_length=50,
        choices=ROLE,
        default=STUDENT,
        verbose_name='Роль',
    )
    phone_number = models.CharField(
        max_length=16,
        blank=True,
        null=True,
        unique=True,
        validators=[validate_phone_number]
    )
    first_name = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    last_name = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    address = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    city = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    state = models.CharField(
        max_length=20,
        blank=True,
        null=True,
    )
    zip_val = models.PositiveIntegerField(
        default=0
    )
    signature = models.BooleanField(default=False)
    username = None

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = CustomUserManager()

    class Meta:
        ordering = ['-id']
        verbose_name = 'Пользователь'
        verbose_name_plural = 'Пользователи'

    def __str__(self):
        return self.email


class UserCourse(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_course')
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='user_course')
    trash_flag = models.BooleanField(default=False)


class UploadedFile(CommonFields):
    file = models.FileField(upload_to='uploads/')
    owner = models.ForeignKey(User, related_name='owner_upload', on_delete=models.CASCADE)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Загрузка'
        verbose_name_plural = 'Загрузки'

    def __str__(self):
        return str(self.id)


class Communication(CommonFields):
    sender = models.ForeignKey(User, related_name='sent_messages', on_delete=models.CASCADE)
    recipient = models.ForeignKey(User, related_name='received_messages', on_delete=models.CASCADE)
    message = models.TextField()
    is_read = models.BooleanField(default=False)
    reading_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Коммуникация'
        verbose_name_plural = 'Коммуникации'

    def __str__(self):
        return f"From: {self.sender.email}, To: {self.recipient.email}"


class Lecture(CommonFields):
    course = models.ForeignKey(
        Course,
        related_name='lecture_course',
        on_delete=models.SET_NULL,
        null=True,
        blank=True
    )
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    content = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Лекция'
        verbose_name_plural = 'Лекции'

    def __str__(self):
        return self.name


class Task(CommonFields):
    course = models.ForeignKey(Course, related_name='task_course', on_delete=models.CASCADE)
    lecture = models.ForeignKey(
        Lecture,
        related_name='task_lecture',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
    )
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    text = models.JSONField(blank=True, null=True)
    type_task = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )

    class Meta:
        ordering = ['-id']
        verbose_name = 'Задача'
        verbose_name_plural = 'Задачи'

    def __str__(self):
        return self.name


class TaskSolution(CommonFields):
    task = models.ForeignKey(Task, related_name='task_solution', on_delete=models.CASCADE)
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    # is_completed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Статус задачи'
        verbose_name_plural = 'Статус задач'

    def __str__(self):
        return str(self.id)


class LectureCompletion(CommonFields):
    lecture = models.ForeignKey(Lecture, on_delete=models.CASCADE)
    student = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Статус лекции'
        verbose_name_plural = 'Статус лекции'

    def __str__(self):
        return str(self.id)

    @property
    def calculate_completion(self):
        tasks = Task.objects.filter(lecture=self.lecture)
        task_solution_total = TaskSolution.objects.filter(task__in=tasks, student=self.student)
        if task_solution_total:
            completion_percentage = (task_solution_total.count() / tasks.count()) * 100
            return completion_percentage > const.is_opened_percent
        return False


class Contacts(CommonFields):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    course = models.ForeignKey(Course, related_name='contact_course', on_delete=models.CASCADE)
    phone_number = models.CharField(
        max_length=16,
        blank=True,
        null=True,
        unique=True,
        validators=[validate_phone_number]
    )
    email = models.EmailField(
        _('email'),
        max_length=254,
        unique=True,
        error_messages={
            'unique': _("A user with that email already exists."),
        },
    )
    first_name = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    last_name = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    country = models.CharField(
        max_length=25,
        blank=True,
        null=True,
    )
    additional = models.CharField(
        max_length=250,
        blank=True,
        null=True,
    )
    activity = models.CharField(
        max_length=250,
        blank=True,
        null=True,
    )

    class Meta:
        ordering = ['-id']
        verbose_name = 'Контакты'
        verbose_name_plural = 'Контакт'

    def __str__(self):
        return str(self.id)


class Settings(CommonFields):
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    description = models.TextField(blank=True, null=True)
    is_flag = models.BooleanField(default=False)
    num = models.IntegerField(default=0)
    float_field = models.FloatField(default=0)
    content = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Настройки'
        verbose_name_plural = 'Настройки'

    def __str__(self):
        return str(self.id)


class Email(CommonFields):
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_emails', verbose_name=_('Sender'))
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_emails', verbose_name=_('Recipient'))
    contact = models.ForeignKey(Contacts, on_delete=models.SET_NULL, related_name='contact_emails', null=True, blank=True, verbose_name=_('Contact'))
    message = models.TextField(verbose_name=_('Message'))
    theme = models.CharField(max_length=25, verbose_name=_('theme'))
    is_read = models.BooleanField(default=False)
    reading_time = models.DateTimeField(null=True, blank=True)

    class Meta:
        verbose_name = _('Email')
        verbose_name_plural = _('Emails')
        ordering = ['-id']

    def __str__(self):
        # return f"From: {self.contact.email}, To: {self.recipient.email}"
        return f"From: {self.sender.id}, To: {self.recipient.id}"


class Template(models.Model):
    name = models.CharField(max_length=100)
    text = models.TextField(blank=True)
    subject = models.CharField(max_length=255, blank=True)
    from_mailbox = models.ForeignKey('Mailbox', on_delete=models.CASCADE, related_name='template')
    files = models.JSONField(default=list, blank=True)

    def __str__(self):
        return self.name


class Mailbox(models.Model):
    PROVIDER_CHOICES = (
        ('google', 'google'),
        ('webmail', 'webmail'),
        ('privateemail', 'privateemail'),
    )
    provider = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    email = models.EmailField()
    password = models.CharField(max_length=255)
    courses = models.ManyToManyField(Course, related_name='mailboxes')
    smtp_server = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.provider} ({self.email})"


class EmailSMTP(CommonFields):
    sender = models.EmailField()
    recipient = models.EmailField()
    subject = models.CharField(max_length=255)
    body = models.TextField()
    sent_at = models.DateTimeField(auto_now_add=True)
    mailbox = models.ForeignKey(Mailbox, on_delete=models.CASCADE, related_name='emailsmtp')
    id_inbox = models.CharField(max_length=100, blank=True, null=True,)
    template = models.ForeignKey(
        Template,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='emailsmtp'
    )
    is_read = models.BooleanField(default=False)
    reading_time = models.DateTimeField(null=True, blank=True)
    is_answer = models.BooleanField(default=False)
    attachments = models.JSONField(default=list, blank=True)

    def __str__(self):
        return str(self.id)
