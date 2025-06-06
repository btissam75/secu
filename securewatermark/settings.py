from pathlib import Path
import os, binascii

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = 'django-insecure-…'
DEBUG = True
ALLOWED_HOSTS = []

# — Media & Static —
MEDIA_ROOT = BASE_DIR / 'media'
MEDIA_URL  = '/media/'
STATIC_URL = '/static/'
STATICFILES_DIRS = [ BASE_DIR / 'watermark' / 'static' ]

# — Applications —
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
'watermark.apps.WatermarkConfig',
    'django.contrib.sites',
    'allauth',
    'allauth.account',

  
]

SITE_ID = 1

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'allauth.account.middleware.AccountMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'securewatermark.urls'
WSGI_APPLICATION = 'securewatermark.wsgi.application'

# — Templates —
TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            os.path.join(BASE_DIR, 'watermark', 'templates'),
            # (éventuellement) os.path.join(BASE_DIR, 'templates')
              
        ],
        
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

# — Base de données (SQLite par défaut) —
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}

# — Validation des mots de passe —
AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
        'OPTIONS': {
            'user_attributes': ('username', 'email'),
            'max_similarity': 0.7,
        },
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
        'OPTIONS': {'min_length': 8},
    },
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
    {'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator'},
]

AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
    'allauth.account.auth_backends.AuthenticationBackend',
]

# — Internationalisation —
LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# — Mail (exemple) —
EMAIL_BACKEND = 'django.core.mail.backends.smtp.EmailBackend'
EMAIL_HOST = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = 'votre.email@exemple.com'
EMAIL_HOST_PASSWORD = 'votre-mot-de-passe-app'
DEFAULT_FROM_EMAIL = 'SecureWaterMark <noreply@votre-domaine.com>'

# — Clé AES (pour votre logic de steganographie) —
AES_KEY = binascii.unhexlify(
    os.environ.get(
        "AES_KEY_HEX",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    )
)

LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/'

USE_DEPRECATED_PYTZ = True
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'
