"""
URL configuration for Vulnsploit project.
"""

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from scanner.views import CookieTokenObtainPairView, CookieTokenRefreshView
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator


class RateLimitedCookieTokenView(CookieTokenObtainPairView):
    @method_decorator(ratelimit(key='ip', rate='10/15m', method='POST', block=True))
    def post(self, request, *args, **kwargs):
        return super().post(request, *args, **kwargs)


def health_check(request):
    return JsonResponse({'status': 'ok', 'service': 'vulnsploit-api'})


urlpatterns = [
    path('admin/',               admin.site.urls),
    path('api/',                 include('scanner.urls')),
    path('api/health/',          health_check,                    name='health_check'),
    path('api/token/',           RateLimitedCookieTokenView.as_view(),  name='token_obtain_pair'),
    path('api/token/refresh/',   CookieTokenRefreshView.as_view(),      name='token_refresh'),
]
