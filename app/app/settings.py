from datetime import timedelta
from pathlib import Path
import os
from django.urls import reverse_lazy
import dotenv

dotenv.load_dotenv('../../.env')

BASE_DIR = Path(__file__).resolve().parent.parent

#SECRET_KEY = os.getenv("SECRET_KEY", 'secret')

#DEBUG = int(os.getenv("DEBUG", 0))
SECRET_KEY = "django-insecure-i0s&6^ksd6$ts60n%5)x=kmx7o46h%%z7)1u!&q1(#ubckfc1z"
DEBUG = True

ALLOWED_HOSTS = os.getenv("DJANGO_ALLOWED_HOSTS", "127.0.0.1 localhost db 185.247.185.219").split(" ")

SITE_DOMAIN = os.getenv("SITE_DOMAIN", None)

FORCE_SCRIPT_NAME = '/'

CORS_ALLOW_HEADERS = (
    'Content-Type',
    'Authorization',
    'Accept',
)


CORS_ALLOWED_ORIGINS = [
    "http://localhost:8080",
    # "https://wonder-tales.netlify.app",
]

CORS_ALLOW_ALL_ORIGINS = False

CORS_ALLOW_CREDENTIALS = True

CORS_EXPOSE_HEADERS = [
    'Content-Type',
]

CSRF_TRUSTED_ORIGINS = [
    'http://127.0.0.1:8043',
    'http://localhost:8043',
] + ([f'https://{SITE_DOMAIN}', f'https://{SITE_DOMAIN}:8443'] if SITE_DOMAIN else [])


INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "rest_framework.authtoken",
    "djoser",
    "drf_yasg",
    "django_rest_passwordreset",
    # "django_celery_beat",
    "corsheaders",
    "lms",
    "nested_admin",
    "django_ses",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    'corsheaders.middleware.CorsMiddleware',
]

if DEBUG:
    INSTALLED_APPS.append("debug_toolbar")
    MIDDLEWARE.insert(0, "debug_toolbar.middleware.DebugToolbarMiddleware")
    import socket  # only if you haven't already imported this
    hostname, _, ips = socket.gethostbyname_ex(socket.gethostname())
    INTERNAL_IPS = [ip[: ip.rfind(".")] + ".1" for ip in ips] + ["127.0.0.1", "10.0.2.2"]

ROOT_URLCONF = "app.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [
            f'{BASE_DIR}/templates/',
        ],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

WSGI_APPLICATION = "app.wsgi.application"


USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

DATABASES = {
    "default": {
        "ENGINE": os.getenv("SQL_ENGINE", "django.db.backends.sqlite3"),
        "NAME": os.getenv("SQL_DATABASE", os.path.join(BASE_DIR, "db.sqlite3")),
        "USER": os.getenv("SQL_USER", "user"),
        "PASSWORD": os.getenv("SQL_PASSWORD", "password"),
        "HOST": os.getenv("SQL_HOST", "localhost"),
        "PORT": os.getenv("SQL_PORT", "5432"),
        'ATOMIC_REQUESTS': True,
    }
}


AUTH_USER_MODEL = 'lms.User'
AUTH_PASSWORD_VALIDATORS = [
    {
        "NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.MinimumLengthValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.CommonPasswordValidator",
    },
    {
        "NAME": "django.contrib.auth.password_validation.NumericPasswordValidator",
    },
]


# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = "en-us"

TIME_ZONE = 'Europe/Istanbul'

USE_I18N = True

USE_TZ = True

RESET_TOKEN_EXPIRY_TIME = 12

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = "static/"
STATIC_ROOT = os.path.join(BASE_DIR, 'static')

MEDIA_URL = '/media/'
MEDIA_ROOT = os.path.join(BASE_DIR, 'media')


DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# CELERY, REDIS
REDIS_URL = os.getenv('REDIS_HOST', '127.0.0.1')
REDIS_PORT = os.getenv('REDIS_PORT', 6379)

CELERY_ACCEPT_CONTENT = ['application/json']
CELERY_BROKER_URL = os.getenv('REDIS_HOST')
CELERY_BACKEND_URL = os.getenv('REDIS_HOST')
CELERY_BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': 3600}
CELERY_TASK_SERIALIZER = 'json'
CELERY_TIMEZONE = os.getenv('TIMEZONE')
CELERY_RESULT_SERIALIZER = 'json'
CELERY_RESULT_BACKEND = f"{os.getenv('REDIS_HOST')}/0"
CELERY_RESULT_EXPIRES = 60

BROKER_URL = os.getenv('REDIS_HOST')
BROKER_TRANSPORT_OPTIONS = {'visibility_timeout': 3600}

REST_FRAMEWORK = {
    'DEFAULT_PERMISSION_CLASSES': [
        'rest_framework.permissions.IsAuthenticated',
    ],
    # 'DEFAULT_AUTHENTICATION_CLASSES': [
    #     'rest_framework.authentication.TokenAuthentication',
    # ],
    'DEFAULT_AUTHENTICATION_CLASSES': [
        'rest_framework_simplejwt.authentication.JWTAuthentication',
    ],
}

# LOGIN_URL = reverse_lazy('login')
LOGIN_REDIRECT_URL = reverse_lazy('schema-swagger-ui')


SWAGGER_SETTINGS = {
    'USE_SESSION_AUTH': False,  # Используйте токен для аутентификации, а не сессии
    'SECURITY_DEFINITIONS': {
        'Bearer': {
            'type': 'apiKey',
            'name': 'Authorization',
            'scheme': 'Bearer',
            'in': 'header'
        }
    },
    'JSON_EDITOR': True,
    'SHOW_REQUEST_HEADERS': True,
}


DJOSER = {
    'PASSWORD_RESET_CONFIRM_URL': '#/password/reset/confirm/{uid}/{token}',
    'ACTIVATION_URL': '#/activate/{uid}/{token}',
    'HIDE_USERS': False,
    'SEND_CONFIRMATION_EMAIL': True,
    'LOGIN_FIELD': 'email',
    'PERMISSIONS': {
        'user_list': [
            'rest_framework.permissions.AllowAny'
        ],
        'user': [
            'rest_framework.permissions.AllowAny',
        ],
    }
}

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=60),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
    'AUTH_HEADER_TYPES': ('Bearer',),
    'ROTATE_REFRESH_TOKENS': True,
    'BLACKLIST_AFTER_ROTATION': True,
}
# yandex
# EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
# EMAIL_HOST = 'smtp.yandex.ru'
# EMAIL_PORT = 465
# EMAIL_USE_TLS = False
# EMAIL_USE_SSL = True
# EMAIL_HOST_USER = os.getenv('EMAIL_HOST_USER')
# EMAIL_HOST_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
# DEFAULT_FROM_EMAIL = os.getenv('EMAIL_HOST_USER')
# FRONTEND_DOMAIN = os.getenv("SITE_DOMAIN_FRONT")

# aws
# EMAIL_BACKEND = 'django_ses.SESBackend'
# AWS_ACCESS_KEY_ID = os.getenv("EMAIL_ACCESS_KEY_ID")
# AWS_SECRET_ACCESS_KEY = os.getenv("EMAIL_SECRET_ACCESS_KEY")
# AWS_SES_REGION_NAME = 'eu-central-1'
# AWS_SES_REGION_ENDPOINT = 'email.eu-central-1.amazonaws.com'
# EMAIL_HOST_USER = os.getenv("SMTP_USERNAME")
# EMAIL_HOST_PASSWORD = os.getenv("SMTP_PASSWORD")


BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DATETIME_FORMATTER = '%d/%b/%Y %H:%M:%S'

LOG_FORMATTER = (
    '[%(asctime)s] %(levelname)s: %(filename)s:%(funcName)s %(message)s'
)
LOG_FILE = os.path.join('/root/lms/app/logs', 'lms.log')
LOG_FILE_WATCHED = os.path.join('/home/lms/app/logs', 'watched_file.log')
# LOG_FILE = os.path.join('/home/app/logs', 'lms.log')
# LOG_FILE_WATCHED = os.path.join('/home/app/logs', 'watched_file.log')

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'console': {
            'format': LOG_FORMATTER,
            'datefmt': DATETIME_FORMATTER,
        },
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'console',
        },
        'timed_rotating_file': {
            'level': 'DEBUG',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'filename': LOG_FILE,
            'formatter': 'console',
            'when': 'midnight',
            'interval': 1,
            'backupCount': 7,
        },
        # 'watched_file': {
        #     'level': 'DEBUG',
        #     'class': 'logging.handlers.WatchedFileHandler',
        #     'filename': LOG_FILE_WATCHED,
        #     'formatter': 'console',
        # },
    },
    'loggers': {
        'main': {
            'level': 'DEBUG',
            'handlers': ['console', 'timed_rotating_file'],
            'propagate': False,
        },
        '': {
            'level': 'INFO',
            'handlers': ['console'],
            'propagate': False,
        },
    },
}
