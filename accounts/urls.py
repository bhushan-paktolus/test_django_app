from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('profile/', views.profile, name='profile'),
    path('profile/upload/', views.profile_picture_upload, name='profile_picture_upload'),
    path('users/', views.user_list, name='user_list'),
    path('users/create/', views.user_create, name='user_create'),
    path('users/<int:user_id>/edit/', views.user_edit, name='user_edit'),
    path('users/<int:user_id>/delete/', views.user_delete, name='user_delete'),
    
    # Password reset URLs
    path('password-reset/', views.password_reset_request, name='password_reset_request'),
    path('password-reset/verify-otp/', views.verify_otp, name='verify_otp'),
    path('password-reset/set-new-password/', views.set_new_password, name='set_new_password'),
    
    # Password change URLs
    path('password-change/', views.password_change, name='password_change'),
    path('password-change/done/', auth_views.PasswordChangeDoneView.as_view(
        template_name='accounts/password_change_done.html'
    ), name='password_change_done'),
] 