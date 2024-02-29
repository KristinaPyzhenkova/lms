from django.contrib import admin
from django.urls import include, path
from django_rest_passwordreset.views import ResetPasswordConfirmViewSet

from app.yasg import urlpatterns as doc_urls


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('lms.urls')),
    # path('password/<str:token>/',
    #      ResetPasswordConfirmViewSet.as_view({'post': 'create'}),
    #      name='reset_password_confirm'),
]
urlpatterns += doc_urls
