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
        return self.name


class User(AbstractUser):
    STUDENT = 'Студент'
    MENTOR = 'Наставник'
    ROLE = (
        (STUDENT, STUDENT),
        (MENTOR, MENTOR),
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
    course = models.ManyToManyField(
        Course,
        related_name='сourse',
        blank=True,
        verbose_name='Курс'
    )
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


class Module(CommonFields):
    course = models.ForeignKey(Course, related_name='module_course', on_delete=models.CASCADE)
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    description = models.TextField(blank=True, null=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Модуль'
        verbose_name_plural = 'Модули'

    def __str__(self):
        return self.name


class Task(CommonFields):
    course = models.ForeignKey(Course, related_name='task_course', on_delete=models.CASCADE)
    module = models.ForeignKey(Module, related_name='task_module', on_delete=models.CASCADE)
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


class Lecture(CommonFields):
    module = models.ForeignKey(Module, related_name='lecture_module', on_delete=models.CASCADE)
    name = models.CharField(
        max_length=100,
        blank=True,
        null=True,
    )
    text = models.TextField()
    additional = models.JSONField(blank=True, null=True)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Лекция'
        verbose_name_plural = 'Лекции'

    def __str__(self):
        return self.name


class TaskSolution(CommonFields):
    task = models.ForeignKey(Task, related_name='task_solution', on_delete=models.CASCADE)
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    is_completed = models.BooleanField(default=False)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Статус задачи'
        verbose_name_plural = 'Статус задач'

    def __str__(self):
        return self.id


class ModuleCompletion(CommonFields):
    module = models.ForeignKey(Module, on_delete=models.CASCADE)
    student = models.ForeignKey(User, on_delete=models.CASCADE)

    class Meta:
        ordering = ['-id']
        verbose_name = 'Статус модуля'
        verbose_name_plural = 'Статус модулей'

    def __str__(self):
        return self.id

    @property
    def is_completed(self):
        tasks = Task.object.filter(module=self.module)
        task_solution_total = TaskSolution.object.filter(task__in=tasks)
        return True if (
            task_solution_total.filter(student=self.student).count() / task_solution_total.count() * 100
        ) > const.is_opened_percent else False


class Contacts(CommonFields):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
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
    additional = models.CharField(
        max_length=250,
        blank=True,
        null=True,
    )