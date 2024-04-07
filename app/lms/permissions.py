from rest_framework import viewsets, permissions

from lms import models

# class IsMentor(permissions.BasePermission):
#     def has_permission(self, request, view):
#         if not request.user.is_authenticated:
#             return False
#         user = request.user
#         if request.method == 'POST':
#             return user.role == models.User.MENTOR
#         course_id = view.kwargs.get('pk')
#         if course_id:
#             # Проверяем, является ли пользователь наставником на этом курсе
#             return user.role == models.User.MENTOR and user.course.filter(id=course_id).exists()
#         return False

class CanView(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated and not view.kwargs:
            return False
        user = request.user
        print(view.kwargs)
        contact_id = view.kwargs.get('pk')
        if contact_id:
            contact = models.Contacts.objects.get(pk=contact_id)
            if user.role == model.User.ADMIN:
                return True
            if user.role == models.User.MENTOR and user.course.filter(id=contact.course.id).exists():
                return True
            if user.role == models.User.STUDENT and user.course.filter(id=contact.course.id).exists():
                return True
        return False

class IsMentor(permissions.BasePermission):
    def has_permission(self, request, view):
        if not request.user.is_authenticated:
            return False
        user = request.user
        return user.role in [models.User.MENTOR, models.User.ADMIN]
