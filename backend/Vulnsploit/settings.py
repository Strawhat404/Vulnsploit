"""
Django settings for Vulnsploit project.
All sensitive values are loaded from environment variables via python-decouple.
Copy backend/.env.example to backend/.env and fill in the values.
"""

from pathlib import Path
from decouple import config, Csv

BASE_DIR = Path(__file__).resolve().parent.parent


# ─── SECURITY ──────────────────────────────────────────────────────────────────

SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = config('ALLOWED_HOSTS', default='localhost,127.0.0.1', cast=Csv())

# HTTPS security headers — active when DEBUG=False
# NOTE: SECURE_SSL_REDIRECT is intentionally OFF because platforms like Render
# and Railway terminate SSL at the load balancer. The app itself receives plain
# HTTP internally. Setting this True on those platforms causes redirect loops.
if not DEBUG:
    SECURE_SSL_REDIRECT          = config('SECURE_SSL_REDIRECT', default=False, cast=bool)
    SECURE_HSTS_SECONDS          = 31536000   # 1 year
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD          = True
    SESSION_COOKIE_SECURE        = True
    CSRF_COOKIE_SECURE           = True
    SECURE_BROWSER_XSS_FILTER    = True
    SECURE_CONTENT_TYPE_NOSNIFF  = True
    X_FRAME_OPTIONS              = 'DENY'
    # Trust Render/Railway/Heroku's X-Forwarded-Proto header
    SECURE_PROXY_SSL_HEADER      = ('HTTP_X_FORWARDED_PROTO', 'https')


# ─── APPLICATIONS ──────────────────────────────────────────────────────────────

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework_simplejwt',
    'corsheaders',
    'csp',
    'django_celery_beat',
    'scanner',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'whitenoise.middleware.WhiteNoiseMiddleware',      # Serve static files on Render/prod
    'corsheaders.middleware.CorsMiddleware',          # Must be before CommonMiddleware
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'csp.middleware.CSPMiddleware',
    'Vulnsploit.middleware.AuditLogMiddleware',
]


# ─── CORS ──────────────────────────────────────────────────────────────────────

CORS_ALLOWED_ORIGINS = config(
    'CORS_ALLOWED_ORIGINS',
    default='http://localhost:5173,http://localhost:3000',
    cast=Csv()
)
CORS_ALLOW_CREDENTIALS = True


# ─── URL / WSGI ────────────────────────────────────────────────────────────────

ROOT_URLCONF = 'Vulnsploit.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'scanner' / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'Vulnsploit.wsgi.application'


# ─── DATABASE ──────────────────────────────────────────────────────────────────

_db_engine = config('DB_ENGINE', default='django.db.backends.sqlite3')

if _db_engine == 'django.db.backends.sqlite3':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / config('DB_NAME', default='db.sqlite3'),
        }
    }
else:
    DATABASES = {
        'default': {
            'ENGINE': _db_engine,
            'NAME':     config('DB_NAME'),
            'USER':     config('DB_USER'),
            'PASSWORD': config('DB_PASSWORD'),
            'HOST':     config('DB_HOST', default='db'),
            'PORT':     config('DB_PORT', default='5432'),
            'OPTIONS': {
                'sslmode': config('DB_SSLMODE', default='require'),
            },
        }
    }


# ─── PASSWORD VALIDATION ───────────────────────────────────────────────────────

AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator'},
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator'},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]


# ─── INTERNATIONALISATION ──────────────────────────────────────────────────────

LANGUAGE_CODE = 'en-us'
TIME_ZONE     = 'UTC'
USE_I18N      = True
USE_TZ        = True


# ─── STATIC FILES ──────────────────────────────────────────────────────────────

STATIC_URL  = 'static/'
STATIC_ROOT = BASE_DIR / 'staticfiles'   # collectstatic writes here
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Media files (uploaded reports, etc.)
MEDIA_URL  = config('MEDIA_URL', default='/media/')
MEDIA_ROOT = config('MEDIA_ROOT', default=str(BASE_DIR / 'media'))

# ─── OBJECT STORAGE (S3 / R2 / compatible) ─────────────────────────────────────
# When AWS_STORAGE_BUCKET_NAME is set, media (PDF reports) are uploaded to S3/R2
# via django-storages instead of the local filesystem. This prevents PDF loss on
# ephemeral filesystems (Render free tier redeploys) and enables multi-instance
# backend deployments. Falls back to local filesystem storage when unset.

_aws_bucket = config('AWS_STORAGE_BUCKET_NAME', default='')
if _aws_bucket:
    INSTALLED_APPS.append('storages')

    AWS_STORAGE_BUCKET_NAME = _aws_bucket
    AWS_S3_REGION_NAME      = config('AWS_S3_REGION_NAME', default='us-east-1')
    # R2 / MinIO / custom endpoint override (leave blank for AWS S3)
    AWS_S3_ENDPOINT_URL     = config('AWS_S3_ENDPOINT_URL', default='')
    AWS_ACCESS_KEY_ID        = config('AWS_ACCESS_KEY_ID', default='')
    AWS_SECRET_ACCESS_KEY    = config('AWS_SECRET_ACCESS_KEY', default='')
    AWS_QUERYSTRING_AUTH     = True   # generate pre-signed URLs for downloads
    AWS_DEFAULT_ACL          = 'private'
    AWS_S3_FILE_OVERWRITE    = False

    STORAGES = {
        'default':     {'BACKEND': 'storages.backends.s3.S3Storage'},
        'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'},
    }
else:
    STORAGES = {
        'default':     {'BACKEND': 'django.core.files.storage.FileSystemStorage'},
        'staticfiles': {'BACKEND': 'whitenoise.storage.CompressedManifestStaticFilesStorage'},
    }

# OpenAI
OPENAI_API_KEY = config('OPENAI_API_KEY', default='')

# ─── EMAIL ──────────────────────────────────────────────────────────────────────

SITE_URL = config('SITE_URL', default='http://localhost:5173')
DEFAULT_FROM_EMAIL = config('DEFAULT_FROM_EMAIL', default='noreply@vulnsploit.com')

EMAIL_BACKEND = config('EMAIL_BACKEND', default='django.core.mail.backends.smtp.EmailBackend')
EMAIL_HOST = config('EMAIL_HOST', default='')
EMAIL_PORT = config('EMAIL_PORT', default=587, cast=int)
EMAIL_HOST_USER = config('EMAIL_HOST_USER', default='')
EMAIL_HOST_PASSWORD = config('EMAIL_HOST_PASSWORD', default='')
EMAIL_USE_TLS = config('EMAIL_USE_TLS', default=True, cast=bool)


# ─── CONTENT SECURITY POLICY ────────────────────────────────────────────────────

# django-csp >= 4.0 format (the old CSP_* settings now fail system checks).
CONTENT_SECURITY_POLICY = {
    'DIRECTIVES': {
        'default-src': ("'self'",),
        'script-src':  ("'self'",),
        'style-src':   ("'self'", "'unsafe-inline'"),
        'img-src':     ("'self'", "data:"),
        'font-src':    ("'self'",),
        'connect-src': ("'self'",),
    },
}


# ─── SIMPLE JWT ─────────────────────────────────────────────────────────────────

from datetime import timedelta

SIMPLE_JWT = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'REFRESH_TOKEN_LIFETIME': timedelta(days=7),
    'ROTATE_REFRESH_TOKENS': True,
}


# ─── CELERY ────────────────────────────────────────────────────────────────────

CELERY_BROKER_URL       = config('CELERY_BROKER_URL',      default='redis://redis:6379/0')
CELERY_RESULT_BACKEND   = config('CELERY_RESULT_BACKEND',  default='redis://redis:6379/0')
CELERY_ACCEPT_CONTENT   = ['application/json']
CELERY_RESULT_SERIALIZER = 'json'
CELERY_TASK_SERIALIZER  = 'json'
CELERY_TASK_TIME_LIMIT  = 3600
CELERY_TASK_SOFT_TIME_LIMIT = 3300

# If using Upstash rediss:// URL, add SSL cert settings automatically
_broker_url = config('CELERY_BROKER_URL', default='redis://redis:6379/0')
if _broker_url.startswith('rediss://'):
    CELERY_BROKER_USE_SSL = {
        'ssl_cert_reqs': 'CERT_NONE',
    }
    CELERY_REDIS_BACKEND_USE_SSL = {
        'ssl_cert_reqs': 'CERT_NONE',
    }


# ─── DJANGO REST FRAMEWORK ─────────────────────────────────────────────────────

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework_simplejwt.authentication.JWTAuthentication',
        'scanner.auth.APIKeyAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': (
        'rest_framework.permissions.IsAuthenticated',
    ),
    'DEFAULT_THROTTLE_CLASSES': [
        'rest_framework.throttling.AnonRateThrottle',
        'rest_framework.throttling.UserRateThrottle',
    ],
    'DEFAULT_THROTTLE_RATES': {
        'anon': '20/hour',
        'user': '1000/hour',
    },
}


# ─── RATE LIMITING ─────────────────────────────────────────────────────────────

SCAN_RATE_LIMIT  = config('SCAN_RATE_LIMIT',  default='20/h')
LOGIN_RATE_LIMIT = config('LOGIN_RATE_LIMIT', default='10/15m')

# Lab/dev only: allow scan targets and webhooks on private, loopback and
# link-local addresses. Leave False in any shared or production deployment —
# otherwise users can scan this server's own network.
ALLOW_PRIVATE_TARGETS = config('ALLOW_PRIVATE_TARGETS', default=False, cast=bool)

# Scans, recon and schedules are only allowed against targets whose ownership
# the user has proven (DNS TXT record or well-known file). Disable only in an
# isolated lab; with it off, any user can scan any public host.
REQUIRE_TARGET_VERIFICATION = config('REQUIRE_TARGET_VERIFICATION', default=True, cast=bool)
TARGET_VERIFICATION_TTL_DAYS = config('TARGET_VERIFICATION_TTL_DAYS', default=90, cast=int)

# Gemini API key for AI-powered report interpretation (free tier)
GEMINI_API_KEY = config('GEMINI_API_KEY', default=None)

# django-ratelimit cache backend
RATELIMIT_USE_CACHE = 'default'

_redis_url = config('REDIS_URL', default='')
if _redis_url:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.redis.RedisCache',
            'LOCATION': _redis_url,
        }
    }
else:
    CACHES = {
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    }


# ─── LOGGING ───────────────────────────────────────────────────────────────────

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '[{levelname}] {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '[{levelname}] {asctime} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'WARNING',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'WARNING',
            'propagate': False,
        },
        'scanner': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}
