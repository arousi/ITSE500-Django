from django.shortcuts import render


def index(request):
    """Render the React single-page app entry point.

    The React build's index.html is placed in `frontend_build` and
    added to TEMPLATE DIRS in settings.py so Django can render it.
    """
    return render(request, 'index.html')