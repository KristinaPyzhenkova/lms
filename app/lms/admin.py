from django import forms
from django.contrib import admin
from django.contrib.admin.widgets import FilteredSelectMultiple
from django.db.models import QuerySet
from django.utils import timezone
from nested_admin import NestedTabularInline, NestedModelAdmin


from lms import models


class CourseAdminForm(forms.ModelForm):
    class Meta:
        model = models.User
        fields = '__all__'

    course = forms.ModelMultipleChoiceField(
        queryset=models.Course.objects.all(),
        required=False,
        widget=FilteredSelectMultiple('Course', is_stacked=False)
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self.instance.pk:
            self.fields['course'].initial = models.Course.objects.filter(
                user_course__in=self.instance.user_course.all()
            )

    def save(self, commit=True):
        user_instance = super().save(commit=False)
        user_instance.save()
        courses = self.cleaned_data.get('course')
        existing_courses = models.Course.objects.filter(user_course__in=self.instance.user_course.all())
        for course in courses:
            if course not in existing_courses:
                models.UserCourse.objects.create(user=user_instance, course=course)
        for course in existing_courses:
            if course not in courses:
                models.UserCourse.objects.filter(user=user_instance, course=course).delete()
        return user_instance


@admin.register(models.UserCourse)
class UserCourseAdmin(admin.ModelAdmin):
    list_display = (
        'user',
        'course',
        'trash_flag',
    )

@admin.register(models.User)
class UserAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'email',
        'email_personal',
        'role',
        'phone_number',
        'first_name',
        'last_name',
        'address',
        'city',
        'state',
        'zip_val',
        'course_list',
        'signature',
    )
    form = CourseAdminForm
    search_fields = ('email',)
    empty_value_display = '-пусто-'
    ordering = ('-id',)
    list_filter = (
        'role',
    )
    list_display_links = ('id',)

    def course_list(self, obj):
        return ", ".join([str(user_course.course) for user_course in obj.user_course.all()])

    course_list.short_description = 'courses'


@admin.register(models.Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'name',
        'description'
    )
    search_fields = ('name',)
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.Communication)
class CommunicationAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'sender',
        'recipient',
        'message',
        'is_read',
        'reading_time',
        'created'
    )
    search_fields = ('sender__email', 'recipient__email')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.Email)
class EmailAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'sender',
        'recipient',
        'contact',
        'theme',
        'message',
        'is_read',
        'reading_time',
        'created'
    )
    search_fields = ('sender__email', 'recipient__email', 'contact__email')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.Lecture)
class LectureAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'course',
        'name',
        'content',
    )
    search_fields = ('sender__email', 'recipient__email')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.Task)
class TaskAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'course',
        'lecture',
        'name',
        'text',
        'type_task'
    )
    search_fields = ('course__name', 'lecture__name')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.TaskSolution)
class TaskSolutionAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'task',
        'student'
    )
    search_fields = ('student__email', 'task__name')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.LectureCompletion)
class LectureCompletionAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'lecture',
        'student',
        'calculate_completion',
    )
    search_fields = ('student__email', 'lecture__name')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.Contacts)
class ContactsAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'user',
        'course',
        'country',
        'phone_number',
        'email',
        'first_name',
        'last_name',
        'additional',
        'activity',
    )
    search_fields = ('user__email', 'email')
    empty_value_display = '-пусто-'
    ordering = ('-id',)


@admin.register(models.UploadedFile)
class UploadedFileAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'file',
        'owner',
        'created',
    )


@admin.register(models.Settings)
class SettingsAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'name',
        'description',
        'is_flag',
        'num',
        'float_field',
        'content'
    )


@admin.register(models.Template)
class TemplateAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'name',
        'text',
        'subject',
        'from_mailbox',
        'files',
    )


class MailboxAdminForm(forms.ModelForm):
    class Meta:
        model = models.Mailbox
        fields = '__all__'

    courses = forms.ModelMultipleChoiceField(
        queryset=models.Course.objects.all(),
        required=False,
        widget=FilteredSelectMultiple('Course', is_stacked=False)
    )


@admin.register(models.Mailbox)
class MailboxAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'provider',
        'email',
        'courses_list',
    )
    form = MailboxAdminForm

    def courses_list(self, obj):
        return ", ".join([str(course) for course in obj.courses.all()])

    courses_list.short_description = 'courses'


@admin.register(models.EmailSMTP)
class EmailSMTPAdmin(admin.ModelAdmin):
    list_display = (
        'id',
        'sender',
        'recipient',
        'subject',
        'body',
        'sent_at',
        'mailbox',
    )
