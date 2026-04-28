import os
import sys

# Write settings.py
settings_content = """import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = 'threatlens-secret-key-change-in-production-xyz123'
DEBUG = True
ALLOWED_HOSTS = ['*']

INSTALLED_APPS = [
    'django.contrib.staticfiles',
    'scanner',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'threatlens.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
            ],
        },
    },
]

WSGI_APPLICATION = 'threatlens.wsgi.application'

MONGODB_URI = os.environ.get('MONGODB_URI', 'mongodb://localhost:27017/')
MONGODB_DB = os.environ.get('MONGODB_DB', 'threatlens')

STATIC_URL = '/static/'
STATICFILES_DIRS = [BASE_DIR / 'static']
DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

DATABASES = {}
"""

# This script sits in the project root alongside manage.py
# so settings.py is at threatlens/settings.py relative to here
here = os.path.dirname(os.path.abspath(__file__))
target = os.path.join(here, 'threatlens', 'settings.py')

with open(target, 'w', encoding='utf-8') as f:
    f.write(settings_content)

print("=" * 50)
print("SUCCESS! settings.py has been fixed.")
print("=" * 50)
print()
print("Now run:  python manage.py runserver")
print()
input("Press Enter to exit...")
