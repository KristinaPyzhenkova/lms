from django.urls import path
from django.utils.translation import gettext_lazy as _
from drf_yasg import openapi
from drf_yasg.inspectors import SwaggerAutoSchema
from drf_yasg.views import get_schema_view
from rest_framework import permissions
from rest_framework import serializers
from django.urls import include

from lms import const


class OKResponseSerializer(serializers.Serializer):
    """This is a sample serializer for showing my intent"""
    data_json = serializers.CharField(
        help_text=_("This is the `json` of the selected object.")
    )


schema_view = get_schema_view(
    openapi.Info(
        title='LMS',
        default_version='v1',
        # description='',
        license=openapi.License(name='BSD License'),
        schemes=['http', 'https'],
    ),
    # url=f'https://{const.SITE_DOMAIN}',
    patterns=[path('api/', include('lms.urls'))],
    public=True,
    permission_classes=(permissions.AllowAny,),
)


urlpatterns = [
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path(
        'swagger.yaml',
        schema_view.without_ui(cache_timeout=0),
        name='schema-yaml'
    ),
]
