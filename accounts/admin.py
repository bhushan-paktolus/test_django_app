from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, PasswordResetOTP, UserActivity
from django.utils.translation import gettext_lazy as _

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'username', 'first_name', 'last_name', 'phone', 'role', 'is_active', 'date_joined')
    list_filter = ('is_active', 'role', 'date_joined')
    search_fields = ('email', 'username', 'first_name', 'last_name', 'phone')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('username', 'first_name', 'last_name', 'phone')}),
        ('Permissions', {'fields': ('role', 'is_active')}),
        ('Important dates', {'fields': ('date_joined', 'last_login')}),
    )

    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'username', 'first_name', 'last_name', 'phone', 'password1', 'password2', 'role', 'is_active'),
        }),
    )

@admin.register(PasswordResetOTP)
class PasswordResetOTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'otp', 'is_used', 'created_at')
    list_filter = ('is_used', 'created_at')
    search_fields = ('user__email', 'otp')
    ordering = ('-created_at',)
    readonly_fields = ('created_at',)

@admin.register(UserActivity)
class UserActivityAdmin(admin.ModelAdmin):
    list_display = ('user', 'activity_type', 'ip_address', 'user_agent', 'timestamp')
    list_filter = ('activity_type', 'timestamp')
    search_fields = ('user__email', 'ip_address', 'user_agent')
    ordering = ('-timestamp',)
    readonly_fields = ('timestamp',)
