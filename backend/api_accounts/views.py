from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_protect
from rest_framework import generics
from rest_framework.permissions import AllowAny

from api_accounts.models import CustomUser
from api_accounts.serializers import CustomUserSerializer
from backend.auth import AuthenticatedAPIView


class UserView(AuthenticatedAPIView):
    @staticmethod
    def get(request):
        return JsonResponse({'username': request.user.username})


@method_decorator(csrf_protect, name='dispatch')
class UserCreate(generics.CreateAPIView):
    queryset = CustomUser.objects.all()
    serializer_class = CustomUserSerializer
    permission_classes = (AllowAny,)
