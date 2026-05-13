"""
URL configuration for Vulnsploit project.
"""

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from django.conf import settings
from django.conf.urls.static import static
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator


class RateLimitedTokenView(TokenObtainPairView):
    @method_decorator(ratelimit(key='ip', rate='10/15m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


def health_check(request):
    return JsonResponse({'status': 'ok', 'service': 'vulnsploit-api'})


urlpatterns = [
    path('admin/',               admin.site.urls),
    path('api/',                 include('scanner.urls')),
    path('api/health/',          health_check,                    name='health_check'),
    path('api/token/',           RateLimitedTokenView.as_view(),  name='token_obtain_pair'),
    path('api/token/refresh/',   TokenRefreshView.as_view(),      name='token_refresh'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
