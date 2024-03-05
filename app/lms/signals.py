from django.db.models.signals import post_save
from django.dispatch import Signal
from django.dispatch import receiver
from django_rest_passwordreset.signals import reset_password_token_created
from django.conf import settings

from lms import models


# @receiver(post_save, sender=models.User)
# def create_task_solutions(sender, instance, created, **kwargs):
#     if instance.role == models.User.STUDENT:
#         module_to_add = models.Module.objects.filter(course__in=instance.course.all())
#         current_module = models.ModuleCompletion.objects.filter(student=instance)
#         current_module_ids = current_module.values_list('task', flat=True)
#         for module in module_to_add:
#             if module.pk not in current_module_ids:
#                 models.ModuleCompletion.objects.create(module=module, student=instance)
#
#         tasks_to_add = models.Task.objects.filter(course__in=instance.course.all())
#         current_tasks = models.TaskSolution.objects.filter(student=instance)
#         current_task_ids = current_tasks.values_list('task', flat=True)
#         for task in tasks_to_add:
#             if task.pk not in current_task_ids:
#                 models.TaskSolution.objects.create(task=task, student=instance)
#

# post_save.connect(create_task_solutions, sender=models.User)


@receiver(post_save, sender=models.Lecture)
def create_lecture_completions(sender, instance, created, **kwargs):
    students = models.User.objects.filter(role=models.User.STUDENT, course=instance.course)
    if created:
        for student in students:
            models.LectureCompletion.objects.create(lecture=instance, student=student)

    tasks_to_add = models.Task.objects.filter(lecture=instance)
    for student in students:
        current_tasks = models.TaskSolution.objects.filter(student=student, task__lecture=instance)
        current_task_ids = current_tasks.values_list('task', flat=True)
        for task in tasks_to_add:
            if task.pk not in current_task_ids:
                models.TaskSolution.objects.create(task=task, student=student)


post_save.connect(create_lecture_completions, sender=models.Lecture)


@receiver(post_save, sender=models.Task)
def create_task_completions(sender, instance, created, **kwargs):
    if created:
        students = models.User.objects.filter(role=models.User.STUDENT, course=instance.course)
        for student in students:
            models.TaskSolution.objects.create(task=instance, student=student)


post_save.connect(create_task_completions, sender=models.Task)


@receiver(reset_password_token_created)
def password_reset_token_created(sender, instance, reset_password_token, *args, **kwargs):
    site_domain_front = 'test'
    context = {
        'current_user': reset_password_token.user,
        'email': reset_password_token.user.email,
        'token': reset_password_token.key,
        'reset_password_url': f"{site_domain_front}/app/password/{reset_password_token.key}",
        'valid_hours': str(settings.RESET_TOKEN_EXPIRY_TIME),
        'site_domain': site_domain_front,
    }
    print(context)
    # email_html_message = render_to_string('user_reset_password.html', context)
    # subject = "Смена пароля Wonder Tales"
    # email_host = const.EMAIL_HOST_USER_RU

    # email_plaintext_message = render_to_string('text.txt', context)

    # msg = EmailMultiAlternatives(
    #     subject,
    #     email_plaintext_message,
    #     email_host,
    #     [reset_password_token.user.email]
    # )
    # msg.attach_alternative(email_html_message, "text/html")
    # msg.send()
