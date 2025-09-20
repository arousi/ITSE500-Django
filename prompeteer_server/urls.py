"""
URL configuration for prompeteer_server project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import TemplateView, RedirectView
from django.urls import re_path
from core.views import index

urlpatterns = [
    # Root landing page
    path('', TemplateView.as_view(template_name='base.html'), name='landing'),
    # Team page with inline context (replace links/images as needed)
    path('team/', TemplateView.as_view(
        template_name='team.html',
        extra_context={
            'team': [
                {
                    'name': 'Sanad AlArousi',
                    'role': 'Full stack Software Engineer',
                    'image': 'img/team/sanad-solo.jpg',  # e.g. '/media/mustafa.jpg'
                    'cv': 'cv/Sanad_AlArousi-CV.pdf',  # place under static/cv/
                    'email': 'sanad.arousi@outlook.com',
                    'phone': '+218911662096',
                    'socials': {
                        'linkedin': 'https://www.linkedin.com/in/sanadalarousi/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base%3B4pkEHpOuRqWHHDGra7x4jg%3D%3D',
                        'github': 'https://github.com/arousi',
                    },
                    'skills': ['django','flutter','git','jira']
                },
                {
                    'name': 'Mohanned Shotshati',
                    'role': 'Web Frontend Software Engineer',
                    'image': 'img/team/mohaned-solo.jpeg',
                    'cv': 'cv/mohanned-shotshati-cv.pdf',  # place under static/cv/
                    'email': 'abdelwahab@example.com',
                    'phone': '+218926784552',
                    'socials': {
                        'linkedin': 'https://www.linkedin.com/in/example-abdelwahab/',
                        'github': 'https://github.com/mohaned2001',
                    },
                    'skills': ['react','javascript','git','jira']
                },
            ]
        }
    ), name='team'),
    # Serve favicon (point to an existing SVG under static/branding)
    path('favicon.ico', RedirectView.as_view(url=settings.STATIC_URL + 'branding/favicon.svg')),
    path('admin/', admin.site.urls),

    path('api/v1/auth_api/', include('auth_api.urls')),
    path('api/v1/user_mang/', include('user_mang.urls')),
    #path('api/v1/chat_api/', include('chat_api.urls')),
    path('api/v1/crypto_api/', include('crypto_api.urls')),
]

# Catch-all: serve landing for any non-API path excluding static/media (must be last)
urlpatterns += [
    re_path(r'^(?!static/|media/).*$' , index),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)