import datetime
import typing
import uuid
import json

import requests
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
from django.db import transaction
from django.http import FileResponse
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from lms import serializers, models, const
from lms.helpers import handle_exceptions, generate_password, log_info
from lms.permissions import IsMentor, CanView


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
                'role': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='role',
                    example='Наставник'
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
        user_data['email'] = const.template_email.format(user_data['first_name'], user_data['last_name'])
        user_data['password'] = generate_password()
        log_info(f"{user_data['password'] = } {user_data['email'] = }")
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
        sent_serializer = serializers.ListCommunicationSerializer([communications], many=True,
                                                                  context={'request': request, 'pk': pk})
        response = Response(sent_serializer.data, status=status.HTTP_200_OK)
        received_messages = communications.filter(recipient=request.user)
        received_messages.update(is_read=True, reading_time=timezone.now())
        return response
    
    @action(
        detail=False,
        methods=['GET'],
        url_path='user',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        responses={
            200: openapi.Response(
                description='HTTP_200_OK',
                schema=serializers.ListUserCommunicationSerializer(),
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def view_user(self, request):
        """Просмотр юзеров с кем начата переписка."""
        user = self.request.user
        users_with_communication = models.User.objects.filter(
            Q(sent_messages__recipient=user) | Q(received_messages__sender=user)
        ).distinct()
        sent_serializer = serializers.ListUserCommunicationSerializer(users_with_communication, many=True)
        return Response(sent_serializer.data, status=status.HTTP_200_OK)


class CourseViewSet(viewsets.ModelViewSet):
    serializer_class = serializers.CourseSerializer

    def get_permissions(self):
        if self.action in ['create', 'update', 'destroy', 'partial_update', 'put']:
            return [IsMentor()]
        else:
            return [permissions.IsAuthenticated()]

    def get_queryset(self):
        user = self.request.user
        return models.Course.objects.filter(user_course__in=user.user_course.all())

    @action(
        detail=True,
        methods=['POST'],
        url_path='contact',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='phone_number',
                    example='+79811110011'
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='email',
                    example='email@mail.ru'
                ),
                'first_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='first_name',
                    example="Test"
                ),
                'last_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='last_name',
                    example="last_name"
                ),
                'country': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='country',
                    example="country"
                ),
                'additional': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='additional',
                    example="additional"
                ),
                'activity': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='activity',
                    example="activity"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def create_contacts(self, request, pk):
        course_id = pk
        if request.user.role == models.User.MENTOR and request.user.user_course.filter(course_id=course_id).exists():
            request_data = request.data
            request_data['course'] = course_id
            serializer = serializers.ContactsSerializer(data=request_data)
            if serializer.is_valid():
                serializer.save(course_id=course_id, user_id=request.user.id)
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)

    @action(
        detail=True,
        methods=['GET'],
        url_path='contacts',
        permission_classes=[IsAuthenticated]
    )
    def get_contact(self, request, pk):
        course_id = pk
        if not request.user.user_course.filter(course_id=course_id).exists():
            return Response({'message': 'Контакт не найден'}, status=404)
        contacts = models.Contacts.objects.filter(course_id=course_id)
        serializer = serializers.ContactsSerializer(contacts, many=True)
        return Response(serializer.data)

    @action(
        detail=False,
        methods=['PUT'],
        url_path='update_contact/(?P<contacts_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'phone_number': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='phone_number',
                    example='+79811110011'
                ),
                'email': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='email',
                    example='email@mail.ru'
                ),
                'first_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='first_name',
                    example="Test"
                ),
                'last_name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='last_name',
                    example="last_name"
                ),
                'additional': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='additional',
                    example="additional"
                ),
                'activity': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='activity',
                    example="activity"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def update_contact(self, request, contacts_id, pk=None):
        try:
            contact = models.Contacts.objects.get(pk=contacts_id, course__user_course__user=request.user)
        except models.Contacts.DoesNotExist:
            return Response({'message': 'Контакт не найден'}, status=404)

        if request.user.role == models.User.MENTOR:
            request_data = request.data
            request_data['course'] = contact.course.pk
            if 'email' not in request_data:
                request_data['email'] = contact.email
            serializer = serializers.ContactsSerializer(contact, data=request_data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)
    
    @action(
        detail=False,
        methods=['DELETE'],
        url_path='contact/(?P<contacts_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def delete_contact(self, request, contacts_id):
        try:
            contact = models.Contacts.objects.get(pk=contacts_id, user=request.user)
        except models.Contacts.DoesNotExist:
            return Response({'message': 'Контакт не найден'}, status=status.HTTP_404_NOT_FOUND)

        if request.user.role == models.User.MENTOR:
            contact.delete()
            return Response({'message': 'Контакт успешно удален'}, status=status.HTTP_204_NO_CONTENT)
        return Response({'message': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)
    

    @action(
        detail=True,
        methods=['POST'],
        url_path='lecture',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='name',
                    example='name'
                ),
                'content': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='контент',
                    example="{'key1': 'value1', 'key2': 'value2'}"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def create_lecture(self, request, pk):
        course_id = pk
        if request.user.role == models.User.MENTOR and request.user.user_course.filter(course_id=course_id).exists():
            request_data = request.data
            request_data['course'] = course_id
            content = request_data['content'].replace("'", '"')
            request_data['content'] = json.loads(content)
            serializer = serializers.LectureSerializer(data=request_data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)

    @action(
        detail=True,
        methods=['GET'],
        url_path='lectures',
        permission_classes=[IsAuthenticated]
    )
    def get_lectures(self, request, pk):
        course_id = pk
        if not request.user.user_course.filter(course_id=course_id).exists():
            return Response({'message': 'Лекция не найдена'}, status=404)
        lectures = models.Lecture.objects.filter(course_id=course_id)
        serializer = serializers.GetLectureSerializer(
            lectures,
            context={'user': request.user},
            many=True
        )
        return Response(serializer.data)
    
    @action(
        detail=True,
        methods=['GET'],
        url_path='lectures_completed',
        permission_classes=[IsAuthenticated]
    )
    def get_lectures_completed(self, request, pk):
        course_id = pk
        if request.user.role == models.User.MENTOR and request.user.user_course.filter(course_id=course_id).exists():
            students_on_course = models.User.objects.filter(user_course__course_id=course_id, role=models.User.STUDENT)
            log_info(f'{students_on_course = }')
            serializer = serializers.LectureWithUserSerializer(
                students_on_course,
                context={'course_id': course_id},
                many=True
            )
            return Response(serializer.data)
        return Response({'message': 'Недостаточно прав'}, status=403)
            
                

    @action(
        detail=False,
        methods=['GET'],
        url_path='lectures/(?P<lecture_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def get_lecture_id(self, request, lecture_id):
        try:
            lecture = models.Lecture.objects.get(pk=lecture_id, course__user_course__user=request.user)
        except models.Lecture.DoesNotExist:
            return Response({'message': 'Лекция не найдена'}, status=404)
        if request.user.role == models.User.MENTOR:
            serializer = serializers.LectureSerializer(lecture)
            return Response(serializer.data)
        else:
            try:
                models.LectureCompletion.objects.get(lecture=lecture, student=request.user)
                serializer = serializers.LectureSerializer(lecture)
                return Response(serializer.data)
            except models.LectureCompletion.DoesNotExist:
                return Response({'message': 'Лекция еще не открыта'}, status=404)

    @action(
        detail=False,
        methods=['PUT'],
        url_path='update_lecture/(?P<lecture_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='name',
                    example='name'
                ),
                'content': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='контент',
                    example="{'key1': 'value1', 'key2': 'value2'}"
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def update_lecture(self, request, lecture_id):
        try:
            lecture = models.Lecture.objects.get(pk=lecture_id, course__user_course__user=request.user)
        except models.Lecture.DoesNotExist:
            return Response({'message': 'Лекция не найдена'}, status=404)
        if request.user.role == models.User.MENTOR:
            request_data = request.data
            request_data['course'] = lecture.course.pk
            if 'content' in request_data:
                content = request_data['content'].replace("'", '"')
                request_data['content'] = json.loads(content)
            log_info(f'{request_data = }')
            serializer = serializers.LectureSerializer(lecture, data=request_data)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)
    
    @action(
        detail=False,
        methods=['DELETE'],
        url_path='lecture/(?P<lecture_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def delete_lecture(self, request, lecture_id):
        try:
            lecture = models.Lecture.objects.get(pk=lecture_id, course__user_course__user=request.user)
        except models.Lecture.DoesNotExist:
            return Response({'message': 'Лекция не найдена'}, status=404)

        if request.user.role == models.User.MENTOR:
            lecture.delete()
            return Response({'message': 'Лекция успешно удалена'}, status=status.HTTP_204_NO_CONTENT)
        return Response({'message': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)


    @action(
        detail=True,
        methods=['POST'],
        url_path='task',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'lecture': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description='lecture',
                    example=1
                ),
                'name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='name',
                    example='name'
                ),
                'text': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='text',
                    example="{'key1': 'value1', 'key2': 'value2'}"
                ),
                'type_task': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='type_task',
                    example='type_task'
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def create_tasks(self, request, pk):
        course_id = pk
        if request.user.role == models.User.MENTOR and request.user.user_course.filter(course_id=course_id).exists():
            lecture = models.Lecture.objects.filter(course_id=course_id)
            if not lecture.exists():
                return Response({'message': 'Недостаточно прав'}, status=403) 
            request_data = request.data
            request_data['course'] = course_id
            text = request_data['text'].replace("'", '"')
            request_data['text'] = json.loads(text)
            serializer = serializers.TaskSerializer(data=request_data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)

    @action(
        detail=False,
        methods=['GET'],
        url_path='tasks/(?P<lecture_id>[0-9]+)/(?P<type_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def get_tasks_lecture_id(self, request, lecture_id, type_id):
        type_task = 'question' if int(type_id) == 1 else 'task'
        if not request.user.user_course.filter(course__lecture_course=lecture_id).exists():
            return Response({'message': 'Лекция не найден'}, status=404)
        tasks = models.Task.objects.filter(lecture_id=lecture_id, type_task=type_task)
        serializer = serializers.TaskSerializer(tasks, many=True, context={'request': request})
        return Response(serializer.data)
    
    @action(
        detail=True,
        methods=['GET'],
        url_path='tasks/(?P<type_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def get_tasks(self, request, pk, type_id):
        type_task = 'question' if int(type_id) == 1 else 'task'
        if not request.user.user_course.filter(course_id=pk).exists():
            return Response({'message': 'Курс не найден'}, status=404)
        tasks = models.Task.objects.filter(course_id=pk, type_task=type_task)
        serializer = serializers.ListTaskSerializer([tasks], many=True, context={'request': request, 'pk': pk})
        return Response(serializer.data)
    
    @action(
        detail=True,
        methods=['GET'],
        url_path='solution_tasks/(?P<type_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def get_task_solution(self, request, pk, type_id):
        type_task = 'question' if int(type_id) == 1 else 'task'
        if not request.user.user_course.filter(course_id=pk).exists():
            return Response({'message': 'Курс не найден'}, status=404)
        tasks = models.Task.objects.filter(course_id=pk, type_task=type_task)
        tasks = models.TaskSolution.objects.filter(task__in=tasks)
        serializer = serializers.TaskSolutionSerializer(tasks, many=True)
        return Response(serializer.data)
    

    @action(
        detail=True,
        methods=['GET'],
        url_path='solution_lectures',
        permission_classes=[IsAuthenticated]
    )
    def get_lecture_solution(self, request, pk):
        if not request.user.user_course.filter(course_id=pk).exists():
            return Response({'message': 'Курс не найден'}, status=404)
        lecture = models.LectureCompletion.objects.filter(lecture__course=pk)
        solved_lecture = [lc for lc in lecture if lc.calculate_completion]
        serializer = serializers.LectureCompletionSerializer(solved_lecture, many=True)
        return Response(serializer.data)
    
    @action(
        detail=False,
        methods=['POST'],
        url_path='solution',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'task': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description='task',
                    example=1
                ),
                'answer': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description='answer',
                    example=1
                )
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def create_task_solution(self, request):
        request_data = request.data
        answer = request_data.pop('answer')
        if request.user.role == models.User.STUDENT:
        # if True:
            try:
                task = models.Task.objects.get(id=request_data['task'], course__user_course__user=request.user)
            except models.Task.DoesNotExist:
                returnResponse({'message': 'Задача не найдена'}, status=404)
            # log_info(f'{task.text["answers"][str(answer)]["is_correct"] = }')
            if task.type_task == 'question' and not task.text["answers"][str(answer)]["is_correct"]:
                return Response({'message': 'Задача решена не верно'}, status=404)
            
            request_data['student'] = request.user.pk
            serializer = serializers.TaskSolutionSerializer(data=request_data)

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=201)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)
    
    @action(
        detail=False,
        methods=['POST'],
        url_path='solutions/(?P<type_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'lecture': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description='lecture',
                    example=1
                ),
                'solutions': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'task': openapi.Schema(
                                type=openapi.TYPE_INTEGER,
                                description='task id',
                                example=1
                            ),
                            'answer': openapi.Schema(
                                type=openapi.TYPE_INTEGER,
                                description='answer id',
                                example=1
                            )
                        },
                    ),
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def create_task_solutions(self, request, type_id):
        type_task = 'question' if int(type_id) == 1 else 'task'
        solutions = request.data.get('solutions', [])
        lecture = request.data.get('lecture')
        correct_count = 0
        total_tasks = models.Task.objects.filter(course__user_course__user=request.user, lecture=lecture, type_task=type_task)
        log_info(f'{total_tasks.count() = } {len(solutions) = }')
        if len(solutions) < total_tasks.count() / 100 * const.is_opened_percent:
            return Response({'message': 'Недостаточно правильных решений'}, status=status.HTTP_404_NOT_FOUND)

        for solution_data in solutions:
            task_id = solution_data.get('task')
            answer_id = solution_data.pop('answer')

            try:
                task = models.Task.objects.get(id=task_id, course__user_course__user=request.user, lecture=lecture)
            except models.Task.DoesNotExist:
                return Response({'message': f'Задача с id={task_id} не найдена'}, status=status.HTTP_404_NOT_FOUND)

            if task.type_task == 'question':
                try:
                    is_correct = task.text["answers"][str(answer_id)]["is_correct"]
                except KeyError:
                    return Response({'message': f'Ответ с id={answer_id} не найден для задачи с id={task_id}'}, status=status.HTTP_404_NOT_FOUND)

                if is_correct:
                    correct_count += 1
            else:
                correct_count += 1
        if correct_count / total_tasks.count() >= const.is_opened_percent / 100:
            for solution_data in solutions:
                solution_data['student'] = request.user.pk
            serializer = serializers.TaskSolutionSerializer(data=solutions, many=True)
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data, status=status.HTTP_201_CREATED)
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response({'message': 'Недостаточно правильных решений'}, status=status.HTTP_404_NOT_FOUND)

    @action(
        detail=False,
        methods=['PUT'],
        url_path='update_task/(?P<task_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'name': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='name',
                    example='name'
                ),
                'text': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='text',
                    example="{'key1': 'value1', 'key2': 'value2'}"
                ),
                'type_task': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='type_task',
                    example='type_task'
                ),
            },
        ),
        responses={
            201: openapi.Response(
                description='OK',
            ),
            400: openapi.Response(
                description='HTTP_400_BAD_REQUEST',
            ),
            401: openapi.Response(
                description='Authentication credentials were not provided.',
            )
        }
    )
    def update_task(self, request, task_id):
        try:
            task = models.Task.objects.get(pk=task_id, course__user_course__user=request.user)
        except models.Task.DoesNotExist:
            return Response({'message': 'Задача не найден'}, status=404)

        if request.user.role == models.User.MENTOR:
            request_data = request.data
            request_data['course'] = task.course.pk
            request_data['lecture'] = task.lecture_id
            if 'text' in request_data:
                text = request_data['text'].replace("'", '"')
                request_data['text'] = json.loads(text)
            log_info(f'{request_data = }')
            serializer = serializers.TaskSerializer(task, data=request_data, context={'request': request})
            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)
            return Response(serializer.errors, status=400)
        return Response({'message': 'Недостаточно прав'}, status=403)
    
    @action(
        detail=False,
        methods=['DELETE'],
        url_path='task/(?P<task_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def delete_task(self, request, task_id):
        try:
            task = models.Task.objects.get(pk=task_id, course__user_course__user=request.user)
        except models.Task.DoesNotExist:
            return Response({'message': 'Задача не найдена'}, status=404)

        if request.user.role == models.User.MENTOR:
            task.delete()
            return Response({'message': 'Задача успешно удалена'}, status=status.HTTP_204_NO_CONTENT)
        return Response({'message': 'Недостаточно прав'}, status=status.HTTP_403_FORBIDDEN)


class ManagerStudentsView(APIView):
    permission_classes = [IsMentor]

    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                'course_id',
                openapi.IN_QUERY,
                description="Id of the course",
                type=openapi.TYPE_INTEGER
            ),
            openapi.Parameter(
                'trash_flag',
                openapi.IN_QUERY,
                description="trash_flag of the course",
                type=openapi.TYPE_INTEGER
            ),
        ],
    )
    def get(self, request):
        filter_params = request.query_params
        course_id = request.query_params.get('course_id')
        trash_flag = request.query_params.get('trash_flag')
        user = request.user
        courses = models.Course.objects.filter(user_course__in=user.user_course.all())
        if course_id:
            courses = courses.filter(id=int(course_id))
        students_with_courses = []
        for course in courses:
            students_on_course = course.user_course.filter(user__role=models.User.STUDENT)
            for student in students_on_course:
                log_info(f'{trash_flag = }')
                if trash_flag is not None and student.trash_flag != int(trash_flag):
                    continue
                students_with_courses.append((student.user, course))
        serializer = serializers.ManagerStudentSerializer(students_with_courses, context={"request": request}, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'data': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'course_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'student_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'trash_flag': openapi.Schema(type=openapi.TYPE_INTEGER),
                        },
                    ),
                ),
            },
            required=['data'],
        ),
        responses={200: 'Success', 400: 'Bad request'},
    )
    def put(self, request):
        user = self.request.user
        if user.role != models.User.MENTOR:
            return Response({'message': 'Недостаточно прав'}, status=404)
        all_courses = models.Course.objects.filter(user_course__in=user.user_course.all())
        data = request.data.get('data')
        if not data:
            return Response({"error": "No data provided."}, status=status.HTTP_400_BAD_REQUEST)
        try:
            with transaction.atomic():
                log_info(f'{data = }')
                for entry in data:
                    log_info(f'{entry = }')
                    course_id = entry.get('course_id')
                    student_id = entry.get('student_id')
                    trash_flag = entry.get('trash_flag')

                    if not all([course_id, student_id]) or trash_flag is None:
                        return Response({"error": "course_id, student_id, and trash_flag are required in each entry."}, status=status.HTTP_400_BAD_REQUEST)

                    course = all_courses.filter(id=course_id).first()
                    if not course:
                        return Response({'message': 'Недостаточно прав'}, status=404)
                    student = models.User.objects.filter(id=student_id).first()
                    user_course = models.UserCourse.objects.filter(user=student, course=course).first()
                    if not user_course:
                        return Response({'message': 'Недостаточно прав'}, status=404)
                    user_course.trash_flag = trash_flag
                    user_course.save()
                
            return Response({"message": "Trash flags updated successfully."}, status=status.HTTP_200_OK)
        except (models.Course.DoesNotExist, models.User.DoesNotExist, models.UserCourse.DoesNotExist):
            return Response({"error": "Course or Student not found."}, status=status.HTTP_404_NOT_FOUND)

class UploadedFileViewSet(viewsets.ViewSet):
    queryset = models.UploadedFile.objects.all()
    parser_classes = (MultiPartParser,)

    @action(
        detail=False,
        methods=['GET'],
        url_path='student/(?P<user_id>[0-9]+)',
        permission_classes=[IsAuthenticated]
    )
    def get_upload_student(self, request, user_id):
        student = get_object_or_404(models.User, id=user_id)
        if request.user.role != models.User.MENTOR or not request.user_course.filter(course_id__in=student.course.all()).exists():
            return Response({'message': 'Студент не относится к ментору'}, status=404)
        files = models.UploadedFile.objects.filter(owner=student)
        serializer = serializers.UploadedFileSerializer(files, many=True)
        return Response(serializer.data)

    @action(
        detail=False,
        methods=['GET'],
        permission_classes=[IsAuthenticated]
    )
    def list_upload(self, request):
        files = models.UploadedFile.objects.filter(owner=request.user)
        serializer = serializers.UploadedFileSerializer(files, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        manual_parameters=[openapi.Parameter(
            name="file",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_FILE,
            required=True,
            description="Document"
        )],
        required=['file']
    )    
    def create(self, request):
        request_data = request.data
        request_data['owner'] = request.user.pk
        file_serializer = serializers.UploadedFileSerializer(data=request_data)
        if file_serializer.is_valid():
            file_serializer.save()
            return Response(file_serializer.data, status=201)
        else:
            return Response(file_serializer.errors, status=400)
    
    @action(
        detail=False,
        methods=['POST'],
        url_path='signature',
        permission_classes=[IsAuthenticated]
    )
    @swagger_auto_schema(
        manual_parameters=[
            openapi.Parameter(
                name="files",
                in_=openapi.IN_FORM,
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(type=openapi.TYPE_FILE),
                required=False,
                description="List of documents (up to 3)"
            )
        ],
    )
    def create_signature(self, request):
        files = request.FILES.getlist('files')
        log_info(f'{files = }')
        owner = request.user.pk
        if request.user.role == models.User.MENTOR:
            return Response({'message': 'Ожидается студент.'}, status=404)

        # Проверяем, что количество файлов не превышает 3
        if len(files) > 3:
            return Response("You can upload up to 3 files at once", status=status.HTTP_400_BAD_REQUEST)

        # Обрабатываем каждый файл
        responses = []
        for file in files:
            file_data = {'file': file, 'owner': owner}
            file_serializer = serializers.UploadedFileSerializer(data=file_data)
            if file_serializer.is_valid():
                file_serializer.save()
                responses.append(file_serializer.data)
            else:
                return Response(file_serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        request.user.signature = True
        request.user.save()
        return Response(responses, status=status.HTTP_201_CREATED)

    @action(
        detail=True,
        methods=['GET'],
        permission_classes=[IsAuthenticated]
    )
    def retrieve_upload(self, request, pk=None):
        try:
            uploaded_file = models.UploadedFile.objects.get(pk=pk)
        except models.UploadedFile.DoesNotExist:
            return Response({'message': 'Файл не найден'}, status=404)
        student = uploaded_file.owner
        if request.user.role == models.User.MENTOR and not request.user_course.filter(course_id__in=student.course.all()).exists():
            return Response({'message': 'Файл принадлежит студенту который не относиться к ментору'}, status=404)
        if request.user.role == models.User.STUDENT and uploaded_file.owner != request.user:
            return Response({'message': 'Недостаточно прав'}, status=404)
        file_path = uploaded_file.file.path
        return FileResponse(open(file_path, 'rb'), as_attachment=True)
    
    @action(
        detail=True,
        methods=['DELETE'],
        permission_classes=[IsAuthenticated]
    )
    def delete_upload(self, request, pk=None):
        try:
            uploaded_file = models.UploadedFile.objects.get(pk=pk, owner=request.user)
            uploaded_file.delete()
            return Response({'message': 'Файл успешно удален'}, status=204)
        except models.UploadedFile.DoesNotExist:
            return Response({'message': 'Файл не найден'}, status=404)
