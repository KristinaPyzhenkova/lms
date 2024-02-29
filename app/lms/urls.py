from rest_framework.routers import SimpleRouter
from django.urls import include, path
from django.conf import settings
from django.conf.urls.static import static

from lms import views

router = SimpleRouter()
router.register('user', views.UserViewSet, basename='user')
router.register('message', views.CommunicationViewSet, basename='message')


urlpatterns = [
    path('', include(router.urls)),
    # path('link/<str:gender>/', views.GenderImageView.as_view()),
    # path('auth/token/login', views_djoser.TokenCreateView.as_view(), name='login'),
    # path('auth/token/logout', views_djoser.TokenDestroyView.as_view(), name='logout'),
    path('auth/', include('djoser.urls.jwt')),
    path('password_reset/', include('django_rest_passwordreset.urls', namespace='password_reset')),
]

if settings.DEBUG:
    urlpatterns.extend(static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT))
    urlpatterns.append(path("__debug__/", include("debug_toolbar.urls")),)
