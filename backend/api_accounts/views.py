import logging

from django.contrib.sites.shortcuts import get_current_site
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_protect, ensure_csrf_cookie
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from api_accounts.models import CustomUser
from api_accounts.serializers import (ChangePasswordSerializer,
                                      CreateCustomUserSerializer)
from api_auth.tokens import account_activation_token
from backend import response
from backend.auth import AuthenticatedAPIView

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class UserView(AuthenticatedAPIView):
    @staticmethod
    def get(request):
        return JsonResponse({'username': request.user.username})


@method_decorator(csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_cookie, name='dispatch')
class UserCreateView(APIView):
    permission_classes = (AllowAny,)

    @staticmethod
    def post(request):
        serialized = CreateCustomUserSerializer(data=request.data)
        if serialized.is_valid() is False:
            logger.warning(serialized.errors)
            return JsonResponse(
                {
                    'detail': 'Invalid data.'
                },
                status=status.HTTP_400_BAD_REQUEST
            )

        serialized.validated_data.pop('password2')
        password = serialized.validated_data.pop('password1')
        user = CustomUser(**serialized.validated_data)
        user.set_password(password)
        user.is_active = False
        user.save()

        current_site = get_current_site(request)
        message = render_to_string('api_accounts/account_activation_email.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': account_activation_token.make_token(user),
        })

        subject = 'Email subject'
        user.email_user(subject, message)

        return JsonResponse(
            {
                'detail': 'Please confirm your e-mail to complete registration.'
            }, status=status.HTTP_200_OK
        )


class ActivateAccountView(APIView):
    @staticmethod
    def get(request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = CustomUser.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, CustomUser.DoesNotExist):
            user = None

        if user is not None and account_activation_token.check_token(user, token):
            user.is_active = True
            user.email_confirmed = True
            user.save()

            return JsonResponse(
                {
                    'detail': 'Your account have been confirmed.'
                }, status=status.HTTP_200_OK)

        return JsonResponse(
            {
                'detail': 'The confirmation link was invalid.'
            }, status=status.HTTP_400_BAD_REQUEST
        )


@method_decorator(csrf_protect, name='dispatch')
@method_decorator(ensure_csrf_cookie, name='dispatch')
class ChangePasswordView(AuthenticatedAPIView):
    @staticmethod
    def put(request):
        if request.user.is_anonymous:
            return response.json_401(
                msg='Only logged in user can change the password.'
            )

        serialized = ChangePasswordSerializer(
            data=request.data,
            context={'request': request}
        )

        if serialized.is_valid() is False:
            logger.warning(serialized.errors)
            return response.json_400(msg='Invalid data.')

        serialized.validated_data.pop('password2')
        password = serialized.validated_data.pop('password1')

        user = CustomUser.objects.get(
            pk=request.user.pk,
            is_active=True,
            email_confirmed=True,
        )

        user.set_password(password)
        user.save()

        return response.json_200(msg='Password changed.')
