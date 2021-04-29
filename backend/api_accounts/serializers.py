from rest_framework import serializers

from api_accounts.models import CustomUser


class CustomUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ('first_name', 'email', 'password')
        extra_kwargs = {'password': {'write_only': True}}
