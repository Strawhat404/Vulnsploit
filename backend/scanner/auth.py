from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.utils import timezone
from .models import APIKey, hash_api_key


class APIKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('ApiKey '):
            return None

        raw_key = auth_header[7:]
        key_hash = hash_api_key(raw_key)

        try:
            key = APIKey.objects.get(key_hash=key_hash, is_active=True)
        except APIKey.DoesNotExist:
            raise AuthenticationFailed('Invalid API key.')

        key.last_used_at = timezone.now()
        key.save(update_fields=['last_used_at'])

        return (key.user, key)
