import typing
from datetime import datetime
import logging
import re
import threading
from typing import Union
from functools import wraps
import time
import random
import string

import requests
import traceback
from typing import Optional
from datetime import timedelta

# import boto3
# import telegram
from PIL import Image
from io import BytesIO

from django.urls import reverse
from django.utils.html import format_html
# from django_celery_beat.models import IntervalSchedule, PeriodicTask
from django.utils import timezone

from lms import const

logger = logging.getLogger('main')


def handle_exceptions(log_to_telegram=False, reraise_exception=False):
    def exceptions_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                log_error_with_traceback(e, log_to_telegram=log_to_telegram)
                if reraise_exception:
                    raise e
        return wrapper
    return exceptions_decorator


def generate_password(length=8):
    characters = string.ascii_letters + string.digits
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


def retry_on_none(max_retries=3, delay=5):
    def retry_decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for _ in range(max_retries):
                result = func(*args, **kwargs)
                if result is not None:
                    return result
                else:
                    log_info(f"Retrying {func.__name__} after {delay} seconds...")
                    time.sleep(delay)
            else:
                log_info(f"Max retries reached. Unable to get a non-None result from {func.__name__}.")
                return None
        return wrapper
    return retry_decorator


def model_link(model, model_name=None, admin_name=None, reverse_name=None):
    model_field_name = model_name or model.__name__.lower()
    admin_name = admin_name or getattr(model._meta, 'verbose_name', None) or model_field_name
    reverse_name = reverse_name or model_field_name

    def model_link_(self, obj):
        foreign_model = getattr(obj, model_field_name)
        if foreign_model:
            url = reverse(
                f'admin:{foreign_model._meta.app_label}_{reverse_name}_change',
                args=[getattr(foreign_model, foreign_model._meta.pk.name)],
            )
            return format_html(f"<a href='{url}'>{foreign_model}</a>")

    model_link_.admin_order_field = model_field_name
    model_link_.short_description = admin_name

    return model_link_


def first_related_link(
        model,
        related_field_name,
        model_name=None,
        admin_name=None,
        reverse_name=None
):
    model_field_name = model_name or model.__name__.lower()
    admin_name = admin_name or getattr(model._meta, 'verbose_name', None) or model_field_name
    reverse_name = reverse_name or model_field_name

    def first_related_link_(self, obj):
        related_manager = getattr(obj, related_field_name)
        related_model = related_manager.first() if related_manager.exists() else None
        if related_model:
            url = reverse(
                f'admin:{related_model._meta.app_label}_{reverse_name}_change',
                args=[getattr(related_model, related_model._meta.pk.name)],
            )
            return format_html(f"<a href='{url}'>{related_model}</a>")

    first_related_link_.admin_order_field = related_field_name
    first_related_link_.short_description = admin_name

    return first_related_link_


def external_url(
        url_attr_name=None,
        url_method=None,
        link_preview_text=None,
        short_description=None
):
    def external_url_(self, obj):
        external_url_value = url_method(obj) if url_method else getattr(obj, url_attr_name)
        if external_url_value:
            return format_html(
                f"<a href='{external_url_value}'>{link_preview_text or external_url_value}</a>"
            )

    external_url_.allow_tags = True
    external_url_.short_description = short_description or url_attr_name

    return external_url_


def external_image(
        url_attr_name=None,
        url_method=None,
        short_description=None,
        image_width=None,
        show_on_click=False,
        button_text='Show Image',
):
    def external_url_(self, obj):
        image_url = url_method(obj) if url_method else getattr(obj, url_attr_name)
        if image_url:
            style_width = '' if image_width is None else f'width: {image_width}px'
            if show_on_click:
                return format_html(
                    f"<div onclick=\"Array.from(document.getElementsByClassName('hidden_images')).forEach(i => i.style.display= (i.style.display === 'none' ? 'block' : 'none'))\">{button_text}</div>"
                    f"<img class='hidden_images' src='{image_url}' style='display: none; {style_width}'>"
                )
            return format_html(
                f"<image src='{image_url}' style='{style_width}'>"
            )

    external_url_.allow_tags = True
    external_url_.short_description = short_description or url_attr_name

    return external_url_


def short_text(attribute, url_attr_name=None):
    def short_text_(self, obj):
        text_value = getattr(obj, attribute)
        if obj.text and len(text_value) > 50:
            return obj.text[:50] + '...'
        else:
            return obj.text

    short_text_.short_description = url_attr_name or attribute
    return short_text_
#
#
# @handle_exceptions(False)
# def download_image(url):
#     response = requests.get(url)
#     if response.status_code == 200:
#         image_bytes = response.content
#         return image_bytes
#     else:
#         log_error('Не удалось загрузить изображение')
#
#
# @handle_exceptions(False)
# def compress_image(processed_image, quality=50, max_size=(1024 * 1024)):
#     image_bytes = BytesIO()
#     processed_image.save(image_bytes, format=processed_image.format, optimize=True)
#     size = len(image_bytes.getvalue())
#     log_info(f'{size = }')
#     if size >= max_size:
#         while quality > 0 and size >= max_size:
#             image_bytes = BytesIO()
#             processed_image.save(image_bytes, format=processed_image.format, quality=quality)
#             size = len(image_bytes.getvalue())
#             log_info(f'{size = }')
#             quality -= 5
#     return image_bytes

#
# @handle_exceptions(False)
# def prepare_image(image, obj=None):
#     processed_image = Image.open(image)
#     if processed_image.mode == 'P':
#         processed_image = processed_image.convert('RGB')
#     file_extension = image.name.split('.')[-1].lower()
#     if file_extension not in ('jpg', 'jpeg', 'png', 'webp', 'tiff', 'avif'):
#         raise ValueError(f"Unsupported image format: {file_extension}")
#     image_bytes = compress_image(processed_image)
#     file_bytes = image_bytes.getvalue()
#     if obj:
#         file_key = f"{obj.user_id}_{obj.id}_{datetime.now().isoformat()}.{file_extension}"
#     else:
#         file_key = f"new_{datetime.now().isoformat()}.{file_extension}"
#     content_type = f'image/{file_extension}'
#     image_url = store_image_file_at_aws(file_key, file_bytes, content_type)
#     return image_url

#
# @handle_exceptions(False)
# def store_file_at_aws(
#         file_key: str,
#         file_bytes: bytes,
#         content_type: Optional[str] = None,
#         s3_bucket_name: str = const.AWS_S3_FILES_BUCKET
# ) -> bool:
#     s3 = boto3.resource(
#         's3',
#         aws_access_key_id=const.AWS_ACCESS_KEY_ID,
#         aws_secret_access_key=const.AWS_SECRET_ACCESS_KEY
#     )
#     s3.Bucket(s3_bucket_name).put_object(
#         Key=file_key,
#         Body=file_bytes,
#         ContentType=content_type,
#     )
#     return True
#
#
# @handle_exceptions(False)
# def store_mj_request_url_at_aws(mj_request, image_url):
#     file_key = f'{mj_request.pid[1:-1]}_{datetime.now().isoformat()}.png'
#     file_bytes = download_image(image_url)
#     aws_image_url = store_image_file_at_aws(file_key, file_bytes)
#
#     return aws_image_url or image_url
#
#
# @handle_exceptions(False)
# def store_image_file_at_aws(file_key, file_bytes, content_type='image/png') -> typing.Optional[str]:
#     success = store_file_at_aws(file_key, file_bytes, content_type)
#     if success:
#         image_url = f'https://{const.AWS_S3_FILES_BUCKET}.s3.eu-north-1.amazonaws.com/{file_key}'
#         return image_url


def log_error(err_msg: str):
    logger.error(err_msg)


def log_info(info_msg: str):
    logger.info(info_msg)
    # if log_to_telegram:
    #     telegram_bot_send_msg(
    #         info_msg
    #     )


def strip_stacktrace(exc: Union[str, Exception]) -> str:
    stacktrace_regex = r"(#[0-9]* 0x.*|Stacktrace:)\n"
    str_without_stacktrace = re.sub(stacktrace_regex, '', str(exc), 0, re.MULTILINE)
    return str_without_stacktrace


def log_error_with_traceback(e: Exception, log_to_telegram=False):
    msg = strip_stacktrace(f'{str(e)}\n{traceback.format_exc()}')
    log_error(msg)
    if log_to_telegram:
        telegram_bot_send_msg(
            msg,
            const.errors_chat_id,
        )


def telegram_bot_send_msg_async(**kwargs):
    def send_tg(**other_kwargs):
        try:
            telegram_bot_token = other_kwargs.pop('telegram_bot_token', None)
            bot = telegram.Bot(token=telegram_bot_token or const.telegram_bot_token)
            bot.send_message(**other_kwargs)
        except Exception as e:
            log_error_with_traceback(e, log_to_telegram=True)
            log_error(f'{other_kwargs["text"] = }')

    if delay := kwargs.pop('delay', None):
        thread = threading.Timer(delay, function=send_tg, kwargs=kwargs)
    else:
        thread = threading.Thread(target=send_tg, kwargs=kwargs)

    thread.start()


def telegram_bot_send_msg(text: str = None,
                          chat_id: str = const.errors_chat_id,
                          chats=None,
                          silent=False,
                          preview=False,
                          markdown=False,
                          telegram_bot_token=None,
                          delay=None):
    if const.telegram_bot_token is None and telegram_bot_token is None:
        return logger.info(f'MESSAGE TO BE SENT TO TELEGRAM:\n{text}')

    send_to = [chat_id] if chat_id else chats or []

    for chat_id in send_to:
        if len(text) > telegram.MAX_MESSAGE_LENGTH:
            for i in range(0, len(text), telegram.MAX_MESSAGE_LENGTH):
                telegram_bot_send_msg_async(
                    chat_id=chat_id,
                    text=text[i: i + telegram.MAX_MESSAGE_LENGTH],
                    disable_web_page_preview=not preview,
                    disable_notification=silent,
                    parse_mode=telegram.ParseMode.HTML if markdown else None,
                    telegram_bot_token=telegram_bot_token,
                    delay=delay,
                )

        else:
            telegram_bot_send_msg_async(
                chat_id=chat_id,
                text=text,
                disable_web_page_preview=not preview,
                disable_notification=silent,
                parse_mode=telegram.ParseMode.HTML if markdown else None,
                telegram_bot_token=telegram_bot_token,
                delay=delay,
            )


# def get_or_create_then_update_task(name: str,
#                                    task: str,
#                                    schedule: Optional[IntervalSchedule] = None,
#                                    one_off: bool = False,
#                                    kwargs: Optional[str] = None) -> PeriodicTask:
#     periodic_task = PeriodicTask.objects.filter(name=name).first()
#     if periodic_task:
#         periodic_task.interval = schedule
#         periodic_task.task = task
#         periodic_task.one_off = one_off
#         periodic_task.kwargs = kwargs or '{}'
#         periodic_task.save()
#     else:
#         periodic_task, _ = PeriodicTask.objects.get_or_create(
#             interval=schedule,
#             name=name,
#             task=task,
#             one_off=one_off,
#             kwargs=kwargs or '{}',
#         )

#     return periodic_task
