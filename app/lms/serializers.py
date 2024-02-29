import re

from django.db.models import Q
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
