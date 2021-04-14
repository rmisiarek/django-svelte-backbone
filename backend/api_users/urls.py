from django.urls import path

from . import views

urlpatterns = [
    path('session/', view=views.SessionView.as_view(), name='api-session'),
    path('csrf/', view=views.GetCSRF.as_view(), name='api-csrf'),
    path('login/', view=views.LoginView.as_view(), name='api-login'),
    path('logout/', view=views.LogoutView.as_view(), name='api-logout'),
    path('user/', view=views.UserView.as_view(), name='api-user'),
]
