from django.shortcuts import render
from django.template.loader import get_template
from django.template import TemplateDoesNotExist
from django.http import HttpResponse
from django.conf import settings
import io

try:
    import segno  # pure-Python QR generator (SVG/PNG)
except Exception:  # If not installed, we'll handle gracefully at runtime
    segno = None


def index(request):
    """Render the React single-page app entry point.

    The React build's index.html is placed in `frontend_build` and
    added to TEMPLATE DIRS in settings.py so Django can render it.
    """
    try:
        # Try SPA build first if present
        get_template('index.html')
        return render(request, 'index.html')
    except TemplateDoesNotExist:
        # Fallback to project landing page
        return render(request, 'base.html')


def landing(request):
    """Render the landing page and embed a QR SVG that points to this server.

    This avoids exposing a separate public QR endpoint.
    """
    qr_svg = None
    qr_target = None
    if segno is not None:
        public_base = getattr(settings, 'PUBLIC_BASE_URL', 'https://itse500-ok.ly').rstrip('/')
        url = f"{public_base}/team/"
        qr_target = url
        qr = segno.make(url, error='M')
        # Use high-contrast black on white for maximum camera compatibility
        buf = io.BytesIO()
        qr.save(buf, kind='svg', scale=10, border=4, dark='#000000', light='#ffffff')
        qr_svg = buf.getvalue().decode('utf-8')
    context = {
        'qr_svg': qr_svg,
        'qr_target': qr_target,
    }
    return render(request, 'base.html', context)