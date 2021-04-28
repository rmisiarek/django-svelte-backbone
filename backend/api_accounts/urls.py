from django.urls import path

from . import views

# api/accounts/
urlpatterns = [
    path('user/', view=views.UserView.as_view(), name='api-user'),
    path('create/', view=views.UserCreate.as_view(), name='api-user-create'),
]
