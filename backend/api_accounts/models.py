from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils.translation import gettext_lazy as _

from api_accounts.managers import CustomUserManager


class CustomUser(AbstractUser):
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name']

    username = None
    # id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    first_name = models.CharField(_('first name'), max_length=150, blank=False, null=False)
    email = models.EmailField(_('email address'), unique=True)
    email_confirmed = models.BooleanField(default=False)

    objects = CustomUserManager()

    def __str__(self):
        return f'[{self.pk}] {self.email}'
