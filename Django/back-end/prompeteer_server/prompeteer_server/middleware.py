import logging

class DebugHeadersMiddleware:
    """
    Middleware to log all incoming request headers for debugging purposes.
    """
    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger('debug_headers')

    def __call__(self, request):
        self.logger.info(f"Incoming request headers: {request.headers}")
        response = self.get_response(request)
        return response
