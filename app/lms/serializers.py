import re

from django.db.models import Count, F, ExpressionWrapper, FloatField, Q
from rest_framework import serializers
from rest_framework.exceptions import ValidationError

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
        print(f'{password = }')
        user = models.User.objects.create(
            **validated_data
        )
        print(f'{user = }')
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

    class Meta:
        model = models.User
        fields = (
            'id',
            'course',
            'email',
            'email_personal',
            'role',
            'first_name',
            'last_name',
            'address',
            'city',
            'state',
            'zip_val',
            'phone_number',
        )


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
        print(validated_data)
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
        user.course.add(course_new)
        return course_new


class LectureSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Lecture
        fields = ['id', 'name', 'content', 'course']


class TaskSerializer(serializers.ModelSerializer):
    class Meta:
        model = models.Task
        fields = ['id', 'course', 'lecture', 'name', 'text', 'type_task']


class ManagerStudentSerializer(serializers.ModelSerializer):
    course_id = serializers.SerializerMethodField()  # Добавляем поле course_id
    course_name = serializers.SerializerMethodField()
    messages_count = serializers.SerializerMethodField()
    tasks_progress = serializers.SerializerMethodField()
    lectures_progress = serializers.SerializerMethodField()

    class Meta:
        model = models.User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'state', 'course_id', 'course_name', 'messages_count', 'tasks_progress', 'lectures_progress']

    def to_representation(self, instance):
        user, course = instance
        mentor = self.context['request'].user
        representation = super().to_representation(user)
        representation['course_id'] = course.id
        representation['course_name'] = course.name
        representation['messages_count'] = models.Communication.objects.filter(Q(sender=mentor, recipient=user) | Q(sender=user, recipient=mentor)).count()
        total_tasks = models.TaskSolution.objects.filter(student=user, task__course=course)
        completed_tasks = total_tasks.filter(is_completed=True)
        representation['tasks_progress'] = f"{completed_tasks.count()}/{total_tasks.count()}"
        total_lectures = models.LectureCompletion.objects.filter(student=user, lecture__course=course)
        completed_lectures = [lecture for lecture in total_lectures if lecture.calculate_completion]
        representation['lectures_progress'] = f"{len(completed_lectures)}/{total_lectures.count()}"
        return representation
    
    def get_course_id(self, obj):
        return None
    
    def get_course_name(self, obj):
        return None

    def get_messages_count(self, obj):
        return None

    def get_tasks_progress(self, obj):
        return None

    def get_lectures_progress(self, obj):
        return None
