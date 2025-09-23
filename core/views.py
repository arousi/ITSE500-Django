"""Core app: simple site views (landing + SPA fallback) and QR embed.

English
- index(request): Render React SPA if built (templates/index.html), otherwise fall back to templates/base.html.
- landing(request): Render base.html and inject a QR SVG that points users to the public Team page.
- Configuration: Set settings.PUBLIC_BASE_URL (e.g., https://itse500-ok.ly) to control the domain encoded in the QR.

العربية
- index(request): يعرض صفحة React إن وُجدت؛ وإلا يعرض صفحة base.html الافتراضية.
- landing(request): يعرض base.html ويُضمّن كود QR يشير إلى صفحة الفريق العامة.
- الإعداد: عيّن PUBLIC_BASE_URL في الإعدادات (مثل https://itse500-ok.ly) لتحديد النطاق في QR.
"""

from django.shortcuts import render
from django.template.loader import get_template
from django.template import TemplateDoesNotExist
from django.http import HttpResponse
from django.conf import settings
import io
from pathlib import Path
import re

try:
    import segno  # pure-Python QR generator (SVG/PNG)
except Exception:  # If not installed, we'll handle gracefully at runtime
    segno = None


def index(request):
    """Serve the SPA if present; otherwise show the project landing page.

    Behavior
    - Try to render templates/index.html (React build output) when available.
    - If not found, fall back to templates/base.html (project landing).

    Returns: HttpResponse
    """
    try:
        # Try SPA build first if present
        get_template('index.html')
        return render(request, 'index.html')
    except TemplateDoesNotExist:
        # Fallback to project landing page
        return render(request, 'base.html')


def landing(request):
    """Render the landing page and embed a QR code that opens the Team page.

    What it does
    - Builds a high-contrast SVG QR (black on white) using segno when installed.
    - Encodes: f"{PUBLIC_BASE_URL}/team/"; defaults to https://itse500-ok.ly/team/ if unset.
    - Passes the SVG as qr_svg to base.html for in-page rendering (no public QR endpoint).

    Returns: HttpResponse
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


def flutter_index(request):
    """Serve Flutter web build index.html from flutter_build directory.

    Expects files from `flutter build web` to be copied into `BASE_DIR/flutter_build`.
    For correct asset URLs, build Flutter with `--base-href /static/flutter-web/` (recommended),
    or post-process index.html to set `<base href="/static/flutter-web/">`.
    """
    index_path = Path(settings.BASE_DIR) / 'flutter_build' / 'index.html'
    try:
        content = index_path.read_text(encoding='utf-8')
    except FileNotFoundError:
        return render(request, 'base.html')

    # Ensure correct base href so relative assets resolve to /static/flutter-web/
    content = re.sub(r"<base[^>]*>", "<base href='/static/flutter-web/'>", content, flags=re.IGNORECASE)
    if '<base' not in content.lower():
        content = re.sub(r"(<head[^>]*>)", r"\1\n  <base href='/static/flutter-web/'>", content, flags=re.IGNORECASE)

    # Harden key asset URLs in case some browsers ignore base during early fetch
    content = content.replace('src="flutter_bootstrap.js"', 'src="/static/flutter-web/flutter_bootstrap.js"')
    content = content.replace('href="manifest.json"', 'href="/static/flutter-web/manifest.json"')
    content = content.replace('href="favicon.png"', 'href="/static/flutter-web/favicon.png"')

    # Inject a tiny normalizer to convert hash URLs (#/path) to clean paths before Flutter initializes
    # This addresses clients with cached older builds that still use hash strategy.
    normalizer = (
        "<script>\n"
        "(function(){\n"
        "  try {\n"
        "    var h = window.location.hash || '';\n"
        "    var needsNormalize = h && h.indexOf('#/') === 0;\n"
    "    if (needsNormalize) {\n"
    "      var newUrl = h.substring(1) + window.location.search;\n"
        "      // Unregister any existing service workers so we fetch fresh assets\n"
        "      var doReload = function(){\n"
        "        try { window.history.replaceState(null, '', newUrl); } catch (e) {}\n"
        "        // Avoid loops: only reload once per session when normalizing\n"
        "        if (!sessionStorage.getItem('swNormalized')) {\n"
        "          sessionStorage.setItem('swNormalized', '1');\n"
        "          window.location.reload();\n"
        "        }\n"
        "      };\n"
        "      if (navigator.serviceWorker && navigator.serviceWorker.getRegistrations) {\n"
        "        navigator.serviceWorker.getRegistrations().then(function(regs){\n"
        "          regs.forEach(function(r){ r.unregister().catch(function(){}); });\n"
        "          doReload();\n"
        "        }).catch(function(){ doReload(); });\n"
        "      } else {\n"
        "        doReload();\n"
        "      }\n"
        "    }\n"
        "  } catch (e) { /* ignore */ }\n"
        "})();\n"
        "</script>\n"
    )
    # Place the script early in <body> so it runs before flutter_bootstrap.js
    if '<body>' in content:
        content = content.replace('<body>', '<body>\n' + normalizer, 1)
    else:
        # Fallback: prepend to content
        content = normalizer + content

    return HttpResponse(content, content_type='text/html; charset=utf-8')