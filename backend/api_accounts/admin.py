from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from api_accounts.models import CustomUser


class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = (
        'email',
        'first_name',
        'email_confirmed',
        'is_active',
        'is_staff',
        'is_superuser',
    )
    list_filter = (
        'email_confirmed',
        'is_active',
        'is_staff',
        'is_superuser',
    )
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Permissions', {'fields': ('email_confirmed', 'is_staff', 'is_active', 'is_superuser')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'first_name', 'password1', 'password2', 'email_confirmed', 'is_staff', 'is_active', 'is_superuser')}
        ),
    )
    search_fields = ('email',)
    ordering = ('email',)


admin.site.register(CustomUser, CustomUserAdmin)
