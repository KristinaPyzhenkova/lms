import re

from django.db.models import Count, F, ExpressionWrapper, FloatField, Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError
from collections import defaultdict

from lms import models, const
from lms.helpers import log_info, handle_exceptions
from lms.validators import validate_phone_number


class NewUserSerializer(serializers.ModelSerializer):
    """
    Сериализатор для создания новых пользователей.
    """
    phone_number = serializers.CharField(max_length=16, required=False,
                                         validators=[validate_phone_number])

    class Meta:
        model = models.User
        fields = (
            'id',
            'email',
            'email_personal',
            'role',
            'first_name',
            'last_name',
            'address',
            'city',
            'state',
            'zip_val',
            'password',
            'phone_number',
        )
        extra_kwargs = {'password': {'write_only': True}}

    def validate_email_personal(self, value):
        """
        Проверка корректности email.
        """
        if not re.match(r"[^@]+@[^@]+\.[^@]+", value):
            raise serializers.ValidationError("Некорректный формат email.")
        if models.User.objects.filter(email_personal__iexact=value).exists():
            raise serializers.ValidationError("Пользователь с таким email уже существует.")
        return value.lower()

    def validate_phone_number(self, value):
        """
        Проверка уникальности номера телефона, если передан.
        """
        if value:
            if models.User.objects.filter(phone_number=value).exists():
                raise serializers.ValidationError("Пользователь с таким номером телефона уже существует.")
        return value

    def create(self, validated_data):
        password = validated_data.pop('password')
        user = models.User.objects.create(
            **validated_data
        )
        user.set_password(password)
        user.save()
        return user


class PasswordSerializer(serializers.ModelSerializer):
    """
    Сериализатор для изменения пароля.
    """

    new_password = serializers.CharField(required=True)
    current_password = serializers.CharField(required=True)

    class Meta:
        model = models.User
        fields = ('new_password', 'current_password')


class ProfileSerializer(serializers.ModelSerializer):
    courses = serializers.SerializerMethodField()

    class Meta:
        model = models.User
        fields = (
            'id',
            'courses',
            'email',
            'email_personal',
            'role',
            'signature',
            'first_name',
            'last_name',
            'address',
            'city',
            'state',
            'zip_val',
            'phone_number',
        )

    def get_courses(self, instance):
        print(f'{instance = }')
        courses = models.Course.objects.filter(user_course__in=self.instance.user_course.all())
        return ", ".join([str(user_course.name) for user_course in courses])


class CommunicationSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(),
        source='sent_messages',
        write_only=True
    )
    recipient = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(),
        source='received_messages',
        write_only=True
    )

    class Meta:
        model = models.Communication
        fields = ['id', 'sender', 'recipient', 'message', 'is_read', 'reading_time']

    def create(self, validated_data):
        sender = validated_data.pop('sent_messages')
        recipient = validated_data.pop('received_messages')
        message = validated_data.pop('message')
        communication = models.Communication.objects.create(
            sender=sender,
            recipient=recipient,
            message=message,
            **validated_data
        )
        return communication


class NestedCommunicationSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Communication
        fields = ['id', 'sender', 'recipient', 'message', 'is_read', 'reading_time']


class ListCommunicationSerializer(serializers.ModelSerializer):
    communication = NestedCommunicationSerializer(source='*', many=True, read_only=True)
    new_msg = serializers.SerializerMethodField()

    class Meta:
        model = models.Communication
        fields = ['communication', 'new_msg']

    def get_new_msg(self, instance):
        pk = self.context['pk']
        sender = models.User.objects.get(pk=pk)
        recipient = self.context['request'].user
        return models.Communication.objects.filter(sender=sender, recipient=recipient, is_read=False).count()


class ListUserCommunicationSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.User
        fields = ['id', 'first_name', 'last_name']


class ContactsSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Contacts
        fields = ['id', 'course', 'phone_number', 'email', 'first_name', 'last_name', 'country', 'additional', 'activity']


class CourseSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Course
        fields = ['id', 'name', 'description']
    
    def create(self, validated_data):
        user = self.context['request'].user
        course_new = models.Course.objects.create(**validated_data)
        models.UserCourse.objects.create(user=user, course=course_new)
        return course_new


class LectureSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Lecture
        fields = ['id', 'name', 'content', 'course']


class GetLectureSerializer(serializers.ModelSerializer):
    is_completed = serializers.SerializerMethodField()

    class Meta:
        model = models.Lecture
        fields = ['id', 'name', 'content', 'course', 'is_completed']
    
    def get_is_completed(self, obj):
        user = self.context['user']
        lecture_completion = models.LectureCompletion.objects.filter(lecture=obj, student=user).first()
        if lecture_completion:
            return lecture_completion.calculate_completion
        return False


class LectureWithUserSerializer(serializers.Serializer):
    lectures = GetLectureSerializer(many=True, read_only=True)

    class Meta:
        model = models.User
        fields = ['id', 'lectures']

    def to_representation(self, instance):
        course_id = self.context['course_id']
        course = instance.user_course.filter(course_id=course_id).first()
        if course:
            course = course.course
            lectures = course.lecture_course.all()
            serialized_lectures = GetLectureSerializer(
                lectures,
                context={'user': instance},
                many=True
            ).data
            return {
                'user_id': instance.id,
                'lectures': serialized_lectures
            }
        else:
            return {
                'user_id': instance.id,
                'lectures': []
            }


class TaskSerializer(serializers.ModelSerializer):
    is_completed = serializers.SerializerMethodField()
    class Meta:
        model = models.Task
        fields = ['id', 'course', 'lecture', 'name', 'text', 'type_task', 'is_completed']
    
    def get_is_completed(self, instance):
        # print(f'{}')
        user = self.context['request'].user
        return models.TaskSolution.objects.filter(task=instance, student=user).exists()


class ListTaskSerializer(serializers.ModelSerializer):
    tasks = TaskSerializer(source='*', many=True, read_only=True)
    new_tasks = serializers.SerializerMethodField()

    class Meta:
        model = models.Task
        fields = ['new_tasks', 'tasks']

    def get_new_tasks(self, instance):
        pk = self.context['pk']
        course = models.Course.objects.get(pk=pk)
        user = self.context['request'].user
        lectures = models.Lecture.objects.filter(course=course)
        open_lectures = models.LectureCompletion.objects.filter(lecture__in=lectures, student=user).values_list('lecture', flat=True)
        tasks = models.Task.objects.filter(lecture__in=open_lectures)
        user_solutions = models.TaskSolution.objects.filter(student=user, task__course=course)
        tasks_to_exclude = user_solutions.values_list('task', flat=True)
        tasks_ = tasks.exclude(pk__in=tasks_to_exclude)
        return tasks_.count()


class LectureCompletionSerializer(serializers.ModelSerializer):
    lecture = serializers.PrimaryKeyRelatedField(
        queryset=models.Lecture.objects.all()
    )
    student = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all()
    )

    class Meta:
        model = models.LectureCompletion
        fields = ['id', 'lecture', 'student']


class TaskSolutionSerializer(serializers.ModelSerializer):
    task = serializers.PrimaryKeyRelatedField(
        queryset=models.Task.objects.all()
    )
    student = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all()
    )

    class Meta:
        model = models.TaskSolution
        fields = ['id', 'task', 'student']

    def create(self, validated_data):
        task = validated_data.pop('task')
        student = validated_data.pop('student')
        try:
            task_solution = models.TaskSolution.objects.get(task=task, student=student)
            log_info(f'{task_solution = }')
        except models.TaskSolution.DoesNotExist:
            task_solution = models.TaskSolution.objects.create(
                task=task,
                student=student,
                **validated_data
            )
            log_info(f'{task_solution = }')
        return task_solution

class ManagerStudentSerializer(serializers.ModelSerializer):
    course_id = serializers.SerializerMethodField()
    course_name = serializers.SerializerMethodField()
    messages_count = serializers.SerializerMethodField()
    tasks_progress = serializers.SerializerMethodField()
    lectures_progress = serializers.SerializerMethodField()
    created = serializers.SerializerMethodField()
    uploads = serializers.SerializerMethodField()
    contacts = serializers.SerializerMethodField()
    trash = serializers.SerializerMethodField()

    class Meta:
        model = models.User
        fields = [
            'id', 'first_name',
            'last_name', 'email', 'phone_number',
            'state', 'course_id', 'course_name',
            'messages_count', 'tasks_progress', 'lectures_progress',
            'created', 'uploads', 'contacts', 'trash'
        ]

    def to_representation(self, instance):
        user, course = instance
        mentor = self.context['request'].user
        representation = super().to_representation(user)
        representation['course_id'] = course.id
        representation['trash'] = models.UserCourse.objects.get(course=course, user=user).trash_flag
        representation['course_name'] = course.name
        representation['messages_count'] = models.Communication.objects.filter(Q(sender=mentor, recipient=user) | Q(sender=user, recipient=mentor)).count()
        total_tasks = models.Task.objects.filter(course=course, type_task='task')
        completed_tasks = models.TaskSolution.objects.filter(student=user, task__in=total_tasks)
        representation['tasks_progress'] = f"{completed_tasks.count()}/{total_tasks.count()}"
        total_lectures = models.LectureCompletion.objects.filter(student=user, lecture__course=course)
        completed_lectures = [lecture for lecture in total_lectures if lecture.calculate_completion]
        representation['lectures_progress'] = f"{len(completed_lectures)}/{total_lectures.count()}"
        total_uploads = models.UploadedFile.objects.filter(owner=user).count()
        representation['uploads'] = f'{total_uploads}/3'
        representation['contacts'] = f'{course.contact_course.all().count()}/10'
        return representation
    
    def get_created(self, instance):
        return instance.created.date().strftime("%d.%m.%Y")
    
    def get_course_id(self, obj):
        return None
    
    def get_course_name(self, obj):
        return None
    
    def get_trash(self, obj):
        return None

    def get_messages_count(self, obj):
        return None

    def get_tasks_progress(self, obj):
        return None

    def get_lectures_progress(self, obj):
        return None
    
    def get_uploads(self, obj):
        return None
    
    def get_contacts(self, obj):
        return None


class UploadedFileSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.UploadedFile
        fields = ['id', 'file', 'owner']


class SettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Settings
        fields = '__all__'
    
    def save(self, **kwargs):
        instance = super().save(**kwargs)
        image = self.validated_data.get('image', None)
        if image:
            instance.image.save(image.name, image, save=True)
        return instance


class EmailSerializer(serializers.ModelSerializer):
    sender = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(),
        source='sent_emails',
        write_only=True
    )
    recipient = serializers.PrimaryKeyRelatedField(
        queryset=models.User.objects.all(),
        source='received_emails',
        write_only=True
    )
    contact = serializers.PrimaryKeyRelatedField(
        queryset=models.Contacts.objects.all(),
        source='contact_emails',
        write_only=True,
    )
    

    class Meta:
        model = models.Email
        fields = ['id', 'sender', 'recipient', 'contact', 'message', 'is_read', 'reading_time']

    def create(self, validated_data):
        sender = validated_data.pop('sent_emails')
        recipient = validated_data.pop('received_emails')
        message = validated_data.pop('message')
        contact = validated_data.pop('contact_emails')
        communication = models.Email.objects.create(
            sender=sender,
            recipient=recipient,
            contact=contact,
            message=message,
            **validated_data
        )
        return communication


class NestedEmailSerializer(serializers.ModelSerializer):
    sender_email = serializers.SerializerMethodField()
    recipient_email = serializers.SerializerMethodField()

    class Meta:
        model = models.Email
        fields = ['id', 'sender_email', 'recipient_email', 'message', 'is_read', 'reading_time']
    
    def get_sender_email(self, obj):
        if obj.sender.role == models.User.MENTOR and obj.contact:
            return obj.contact.email
        return obj.sender.email
    
    def get_recipient_email(self, obj):
        if obj.recipient.role == models.User.MENTOR and obj.contact:
            return obj.contact.email
        return obj.recipient.email


class ListEmailSerializer(serializers.ModelSerializer):
    email = NestedEmailSerializer(source='*', many=True, read_only=True)
    new_msg = serializers.SerializerMethodField()

    class Meta:
        model = models.Email
        fields = ['email', 'new_msg']

    def get_new_msg(self, instance):
        return instance.filter(is_read=False, recipient=self.context['request'].user).count()


class ListEmailContactSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.Contacts
        fields = ['id', 'email']

class ListEmailStudentsSerializer(serializers.ModelSerializer):

    class Meta:
        model = models.User
        fields = ['id', 'email']
