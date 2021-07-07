import marshmallow
from django.contrib.auth.password_validation import (get_password_validators,
                                                     validate_password)
from django.core import exceptions
from marshmallow import validate

from api_accounts.models import CustomUser
from backend.settings.development import AUTH_PASSWORD_VALIDATORS

# TODO: change AUTH_PASSWORD_VALIDATORS import


class AccountCreateValidator(marshmallow.Schema):
    email = marshmallow.fields.Email(required=True, load_only=True)
    first_name = marshmallow.fields.Str(
        required=True,
        load_only=True,
    )
    password1 = marshmallow.fields.Str(
        required=True,
        load_only=True,
        validate=[validate.Length(8, None)]
    )
    password2 = marshmallow.fields.Str(
        required=True,
        load_only=True,
    )

    @marshmallow.validates_schema
    def validate_passwords(self, data, **_kwargs):
        _passwords_validator(
            password1=data.get('password1', ''),
            password2=data.get('password2', ''),
            user=self.context.get('request')
        )


class ChangePasswordValidator(marshmallow.Schema):
    old_password = marshmallow.fields.Str(
        required=True,
        load_only=True,
        validate=[validate.Length(8, None)]
    )
    password1 = marshmallow.fields.Str(
        required=True,
        load_only=True,
        validate=[validate.Length(8, None)]
    )
    password2 = marshmallow.fields.Str(
        required=True,
        load_only=True,
    )

    @marshmallow.validates_schema
    def validate_passwords(self, data, **_kwargs):
        _passwords_validator(
            password1=data.get('password1', ''),
            password2=data.get('password2', ''),
            user=self.context.get('request')
        )

    @marshmallow.validates_schema
    def validate_old_password(self, data, **_kwargs):
        user = self.context.get('user', None)
        if user:
            if not user.check_password(data['old_password']):
                raise marshmallow.ValidationError(
                    'Old password is not correct.', 'old_password'
                )


class EmailValidator(marshmallow.Schema):
    email = marshmallow.fields.Email(required=True, load_only=True)


class SetPasswordValidator(marshmallow.Schema):
    password1 = marshmallow.fields.Str(
        required=True,
        load_only=True,
        validate=[validate.Length(8, None)]
    )
    password2 = marshmallow.fields.Str(
        required=True,
        load_only=True,
    )

    @marshmallow.validates_schema
    def validate_passwords(self, data, **_kwargs):
        _passwords_validator(
            password1=data.get('password1', ''),
            password2=data.get('password2', ''),
            user=self.context.get('request')
        )


def _passwords_validator(password1: str, password2: str, user: CustomUser = None):
    if password1 != password2:
        raise marshmallow.ValidationError('Passwords do not match.', 'password1')

    try:
        validate_password(
            password=password1,
            user=user,
            password_validators=get_password_validators(
                AUTH_PASSWORD_VALIDATORS
            )
        )
    except exceptions.ValidationError as e:
        raise marshmallow.ValidationError(e.messages, 'password1')
