from django.shortcuts import render
from django.template.loader import get_template
from django.template import TemplateDoesNotExist


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