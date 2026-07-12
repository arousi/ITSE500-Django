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
from core.views import index, landing, flutter_index, healthz
from django.http import HttpRequest

from django.template.loader import get_template
from django.template import TemplateDoesNotExist
from django.http import JsonResponse
import importlib.util as _imp
import importlib


def healthz(request):
    """Lightweight liveness probe for Traefik/orchestrator healthchecks.

    Deliberately does not touch the database (keeps it cheap and avoids
    false negatives under DB connection pressure); the DB-touching check
    used by the app itself is auth_api's /api/v1/auth_api/health/.
    """
    return JsonResponse({"status": "ok"})

# Serve SPA at root when using the React or Flutter subdomains; otherwise keep landing
def root_router(request: HttpRequest):
    # React SPA is the primary site at '/'. The Flutter web build lives under
    # '/app/' and the team/landing page under '/team/' and '/landing/'.
    host = request.get_host().split(':')[0].lower()
    if host == 'flutter.itse500-ok.ly':  # legacy dedicated Flutter host
        return flutter_index(request)
    return index(request)

urlpatterns = [
    # Root: React SPA (primary site)
    path('', root_router, name='root'),
    # Liveness probe (no DB/auth) for nginx / Docker / Traefik healthchecks
    path('healthz', healthz, name='healthz'),
    # Flutter web build served under /app/.
    path('app/', flutter_index, name='flutter-web'),
    # Without this, '/app' (no trailing slash) falls through to the React catch-all below
    # instead of serving Flutter. Redirect it to the canonical '/app/'.
    path('app', RedirectView.as_view(url='/app/', permanent=False)),
    # Flutter owns its ENTIRE subtree: any deep path under /app/ (client-side
    # routes, refreshes, deep links) must serve the Flutter shell, NOT fall
    # through to the React catch-all at the bottom of this list. (Flutter's own
    # assets live under /static/flutter-web/, so this never shadows them.)
    re_path(r'^app/.+$', flutter_index, name='flutter-web-deep'),
    # Landing page with QR (moved off root)
    path('landing/', landing, name='landing'),
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
                    'cv': 'cv/mohaned-cv.pdf',  # place under static/cv/
                    'email': 'mhndalshtshaty93@gmail.com',
                    'phone': '+218926784552',
                    'socials': {
                        'linkedin': 'https://www.linkedin.com/in/%D9%85%D9%87%D9%86%D8%AF-%D8%A7%D9%84%D8%B4%D8%B7%D8%B4%D8%A7%D8%B7%D9%8A-900b17385/overlay/about-this-profile/?lipi=urn%3Ali%3Apage%3Ad_flagship3_profile_view_base%3Ban4yFvhXSy2b9wVrYQhNWg%3D%3D',
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
    # Removed public QR generator endpoint to avoid exposing it

    # Root-level liveness probe (Traefik healthcheck target)
    path('healthz', healthz, name='healthz'),
    path('healthz/', healthz),

    # /api/v1/* is served by django-bolt (each app's api.py, autodiscovered by
    # runbolt) — the DRF includes and drf-spectacular docs routes are gone.
]

# Catch-all: serve SPA or landing for any non-API path excluding static/media (must be last)
urlpatterns += [
    re_path(r'^(?!static/|media/|api/).*$' , root_router),
]

# In DEBUG, prefer serving the Flutter SPA for any non-API/static/media paths to simplify local testing
from django.conf import settings as _settings
if _settings.DEBUG:
    # Place this earlier so it takes precedence in development
    urlpatterns = [
        re_path(r'^(?!static/|media/|api/|admin/|team/|__debug__/|silk/|healthz).*$' , flutter_index),
    ] + urlpatterns

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
    try:
        import debug_toolbar  # type: ignore
        urlpatterns = [path('__debug__/', include('debug_toolbar.urls'))] + urlpatterns
    except Exception:
        pass
    try:
        urlpatterns += [path('silk/', include('silk.urls', namespace='silk'))]
    except Exception:
        pass