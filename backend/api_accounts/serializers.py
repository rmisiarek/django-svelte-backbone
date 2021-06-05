from django.utils.html import escape
from rest_framework import serializers

from api_accounts.models import CustomUser


class CreateCustomUserSerializer(serializers.ModelSerializer):
    email = serializers.EmailField()
    password1 = serializers.CharField(write_only=True)
    password2 = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser
        fields = ('first_name', 'email', 'password1', 'password2')

    def validate(self, attrs):
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 is None or password2 is None:
            raise serializers.ValidationError('Passwords do not match.')

        if password1 != password2:
            raise serializers.ValidationError('Passwords do not match.')

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
        password1 = attrs.get('password1')
        password2 = attrs.get('password2')

        if password1 is None or password2 is None:
            raise serializers.ValidationError('Passwords do not match.')

        if password1 != password2:
            raise serializers.ValidationError('Passwords do not match.')

        return attrs

    def validate_old_password(self, value):
        print('context = ', self.context)
        user = self.context['request'].user
        print('user = ', user)
        if not user.check_password(value):
            raise serializers.ValidationError('Old password is not correct.')

        return value
