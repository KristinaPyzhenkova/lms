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
        return ", ".join([str(course) for course in obj.course.all()])

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
