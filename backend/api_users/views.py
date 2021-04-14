from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.middleware.csrf import get_token
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import ensure_csrf_cookie
from rest_framework.authentication import (BasicAuthentication,
                                           SessionAuthentication)
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView


class AuthenticatedAPIView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]
    permission_classes = [IsAuthenticated]


@method_decorator(ensure_csrf_cookie, name='dispatch')
class SessionView(APIView):
    authentication_classes = [SessionAuthentication, BasicAuthentication]

    @staticmethod
    def get(request):
        if request.user.is_authenticated:
            return JsonResponse({'isAuthenticated': True})
        return JsonResponse({'isAuthenticated': False})


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
                }, status=400
            )

        if username == '' or password == '':  # noqa: B105
            return JsonResponse(
                {
                    'detail': 'Please provide username and password.'
                }, status=400
            )

        user = authenticate(username=username, password=password)

        if user is None:
            return JsonResponse({'detail': 'Invalid credentials.'}, status=400)

        login(request, user)

        return JsonResponse({'detail': 'OK'}, status=200)


class LogoutView(AuthenticatedAPIView):
    @staticmethod
    def get(request):
        if not request.user.is_authenticated:
            return JsonResponse({'detail': 'You are not logged in.'}, status=400)

        logout(request)

        return JsonResponse({'detail': 'Successfully logged out.'})


class GetCSRF(APIView):
    @staticmethod
    def get(request):
        response = JsonResponse({'detail': 'OK'})
        response['X-CSRFToken'] = get_token(request)
        return response


class UserView(AuthenticatedAPIView):
    @staticmethod
    def get(request):
        return JsonResponse({'username': request.user.username})
