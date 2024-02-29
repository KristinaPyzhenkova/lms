import datetime
import typing
import uuid

import requests
import stripe
from dateutil.relativedelta import relativedelta
from django.db.models import Q
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt
from djoser.views import TokenCreateView
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework import permissions, status, viewsets
from rest_framework.authtoken.models import Token
from rest_framework.decorators import action, permission_classes
from rest_framework.exceptions import (
    ValidationError,
    NotFound,
    PermissionDenied,
)
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from lms import serializers, models, const
from lms.helpers import handle_exceptions, generate_password


@permission_classes([permissions.AllowAny, ])
class UserViewSet(viewsets.ViewSet):
    @action(
        detail=False,
        methods=['POST'],
        url_path='set_password',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'current_password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Current password',
                    example='12345'
                ),
                'new_password': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='New password',
                    example='test'
                ),
            },
            required=['current_password', 'new_password'],
        ),
        responses={
            201: openapi.Response(
                description='Password updated successfully',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    @handle_exceptions(True)
    def change_password(self, request):
        """
        Смена пароля.
        """
        serializer = serializers.PasswordSerializer(data=request.data)
        author = request.user
        if not serializer.is_valid(raise_exception=True):
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        if not author.check_password(
            serializer.data.get('current_password')
        ):
            return Response(
                {'current_password': ['Wrong password.']},
                status=status.HTTP_400_BAD_REQUEST
            )
        author.set_password(serializer.data.get('new_password'))
        author.save()
        response = {
            'status': 'success',
            'code': status.HTTP_201_CREATED,
            'message': 'Password updated successfully'
        }
        return Response(response)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'email_personal': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='email',
                    example='test@mail.ru'
                ),
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='phone_number',
                    example='+79811330719'
                ),
                'first_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='first_name',
                    example='Test'
                ),
                'last_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='last_name',
                    example='Test'
                ),
                'address': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='address',
                    example='address'
                ),
                'city': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='city',
                    example='city'
                ),
                'state': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='state',
                    example='state'
                ),
                'zip_val': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='zip_val',
                    example=1234
                ),
            },
            required=['email_personal', 'first_name', 'last_name']
        ),
        responses={
            201: openapi.Response(
                description='HTTP_201_CREATED',
            ),
            400: openapi.Response(
                description='A user with that email already exists.',
            ),
        },
    )
    def create(self, request):
        """Регистрация."""
        user_data = request.data
        user_data['role'] = models.User.STUDENT
        user_data['email'] = const.template_email.format(user_data['first_name'], user_data['last_name'])
        user_data['password'] = generate_password()
        serializer = serializers.NewUserSerializer(
            data=user_data,
            context={'request': request}
        )
        if not serializer.is_valid(raise_exception=True):
            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        user = serializer.save()
        # email_sent()
        return Response(status=status.HTTP_201_CREATED)

    @action(
        detail=False,
        methods=['GET'],
        permission_classes=[IsAuthenticated]
    )
    def profile(self, request):
        """Просмотр профиля по идентификатору."""
        serializer = serializers.ProfileSerializer(self.request.user)
        return Response(serializer.data)


@permission_classes([IsAuthenticated, ])
class CommunicationViewSet(viewsets.ViewSet):

    def get_queryset(self):
        user = self.request.user
        return models.Communication.objects.filter(Q(sender=user) | Q(recipient=user)).order_by('created')

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'recipient': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description='recipient',
                    example=3
                ),
                'message': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='message',
                    example='Hello!'
                ),
            },
            required=['recipient', 'message']
        ),
        responses={
            201: openapi.Response(
                description='HTTP_201_CREATED',
            ),
        },
    )
    def create(self, request):
        print(request.data)
        recipient_id = request.data.get('recipient')
        message = request.data.get('message')
        if not recipient_id or not message:
            return Response({"error": "Recipient ID and message are required."}, status=status.HTTP_400_BAD_REQUEST)

        user_data = request.data
        user_data['sender'] = request.user.id
        serializer = serializers.CommunicationSerializer(data=user_data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @action(
        detail=True,
        methods=['GET'],
        url_path='view',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        responses={
            200: openapi.Response(
                description='HTTP_200_OK',
                schema=serializers.ListCommunicationSerializer(),
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def view(self, request, pk):
        """Просмотр переписки."""
        communications = self.get_queryset().filter(
            Q(sender=pk) | Q(recipient=pk)
        ).order_by('created')
        sent_serializer = serializers.ListCommunicationSerializer([communications], many=True, context={'request': request, 'pk': pk})
        response = Response(sent_serializer.data, status=status.HTTP_200_OK)
        received_messages = communications.filter(recipient=request.user)
        received_messages.update(is_read=True, reading_time=timezone.now())
        return response