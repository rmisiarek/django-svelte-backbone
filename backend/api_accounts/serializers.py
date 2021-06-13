from django.contrib.auth.password_validation import (get_password_validators,
                                                     validate_password)
from django.core import exceptions
from django.utils.html import escape
from rest_framework import serializers

from api_accounts.models import CustomUser
# TODO: change that:
from backend.settings.development import AUTH_PASSWORD_VALIDATORS


class CreateCustomUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('first_name', 'email', 'password1', 'password2')

    def validate(self, attrs):
        password1 = attrs.get('password1', '')
        password2 = attrs.get('password2', '')

        _passwords_validator(password1=password1, password2=password2)

        return attrs

    @staticmethod
    def validate_first_name(value):
        return escape(value)

    @staticmethod
    def validate_email(value):
        lower_email = value.lower()
        if CustomUser.objects.filter(email__iexact=lower_email).exists():
            raise serializers.ValidationError("Invalid e-mail address.")

        return lower_email


class ChangePasswordSerializer(serializers.ModelSerializer):
    password1 = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    old_password = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = CustomUser
        fields = ('old_password', 'password1', 'password2')

    def validate(self, attrs):
        password1 = attrs.get('password1', '')
        password2 = attrs.get('password2', '')

        _passwords_validator(password1=password1, password2=password2)

        return attrs

    def validate_old_password(self, value):
        user = self.context['request'].user
        if not user.check_password(value):
            raise serializers.ValidationError('Old password is not correct.')

        return value


def _passwords_validator(password1: str, password2: str):
    if password1 == '' or password2 == '':
        raise serializers.ValidationError('Passwords do not match.')

    if password1 != password2:
        raise serializers.ValidationError('Passwords do not match.')

    try:
        validate_password(
            password=password1,
            password_validators=get_password_validators(
                AUTH_PASSWORD_VALIDATORS
            )
        )
    except exceptions.ValidationError as e:
        raise exceptions.ValidationError({
            'password': e.messages
        })
