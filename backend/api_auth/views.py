from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.authentication import (BasicAuthentication,
                                           SessionAuthentication)
from rest_framework.views import APIView


class SessionView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    @staticmethod
    def get(request):
        if request.user.is_authenticated:
            return JsonResponse({'auth': True}, status=status.HTTP_200_OK)

        return JsonResponse({'auth': False}, status=status.HTTP_200_OK)


@method_decorator(csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_cookie, name='dispatch')
class LoginView(APIView):
    @staticmethod
    def post(request):
        username = request.data.get('username')
        password = request.data.get('password')

        if username is None or password is None:
            return JsonResponse(
                {
                    'detail': 'Please provide username and password.'
                }, status=status.HTTP_400_BAD_REQUEST
            )

        if username == '' or password == '':  # noqa: B105
            return JsonResponse(
                {
                    'detail': 'Please provide username and password.'
                }, status=status.HTTP_400_BAD_REQUEST
            )

        user = authenticate(username=username, password=password)

        if user is None:
            return JsonResponse(
                {
                    'detail': 'Invalid credentials.'
                }, status=status.HTTP_400_BAD_REQUEST
            )

        login(request, user)

        return JsonResponse({'detail': 'OK'}, status=status.HTTP_200_OK)


class LogoutView(APIView):
    @staticmethod
    def get(request):
        if not request.user.is_authenticated:
            return JsonResponse(
                {
                    'detail': 'You are not logged in.'
                }, status=status.HTTP_401_UNAUTHORIZED
            )

        logout(request)

        return JsonResponse(
            {
                'detail': 'Successfully logged out.'
            }, status=status.HTTP_200_OK
        )


class GetCSRF(APIView):
    @staticmethod
    def get(request):
        response = JsonResponse({'detail': 'OK'}, status=status.HTTP_200_OK)
        response['X-CSRFToken'] = get_token(request)

        return response
