from django.urls import path

from . import views

# api/accounts/
urlpatterns = [
    path(
        route='user/',
        view=views.UserView.as_view(),
        name='api-user'
    ),

    path(
        route='create/',
        view=views.UserCreateView.as_view(),
        name='api-user-create'
    ),

    path(
        route='activate/<uidb64>/<token>/',
        view=views.ActivateAccountView.as_view(),
        name='api-accounts-activate'
    ),

    path(
        route='change-password/',
        view=views.ChangePasswordView.as_view(),
        name='api-accounts-change-password'
    ),
]
