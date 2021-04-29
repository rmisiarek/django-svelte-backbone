from django.contrib.sites.shortcuts import get_current_site
from django.http import JsonResponse
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_protect
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView

from api_accounts.models import CustomUser
from api_accounts.serializers import CustomUserSerializer
from api_auth.tokens import account_activation_token
from backend.auth import AuthenticatedAPIView


class UserView(AuthenticatedAPIView):
    @staticmethod
    def get(request):
        return JsonResponse({'username': request.user.username})


@method_decorator(csrf_protect, name='dispatch')
class UserCreateView(APIView):
    permission_classes = (AllowAny,)

    @staticmethod
    def post(request):
        serialized = CustomUserSerializer(data=request.data)
        if serialized.is_valid() is False:
            return JsonResponse({'detail': 'Serialization failed'}, status=400)

        password = serialized.validated_data.pop('password')
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
            }, status=200
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
            return JsonResponse({'detail': 'Your account have been confirmed.'}, status=200)

        return JsonResponse(
            {
                'detail': 'The confirmation link was invalid.'
            }, status=400
        )
