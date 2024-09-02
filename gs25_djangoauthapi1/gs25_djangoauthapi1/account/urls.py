from django.urls import path
from account.views import UserRegistrationView, UserLoginView, UserProfileView, UserChangePassword, SendPasswordResetEmailView, UserPasswordResetView

urlpatterns = [
    path('register/', UserRegistrationView.as_view(), name = 'register'),
    path('login/', UserLoginView.as_view(), name = 'lokgin'),
    path('profile/', UserProfileView.as_view(), name = 'profile'),
    path('changepassword/', UserChangePassword.as_view(), name = 'changepassword'),
    path('send-reset-password-email/', SendPasswordResetEmailView.as_view(), name = 'send-reset-password-email'),
    path('reset-password/<user_id>/<token>/', UserPasswordResetView.as_view(), name = 'reset-password'),
    
]
