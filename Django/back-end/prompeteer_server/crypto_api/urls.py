from django.urls import path
from .views import UserUMKView

urlpatterns = [
    path('umk/', UserUMKView.as_view(), name='user-umk'),
]
