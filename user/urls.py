from django.urls import path, include
from .views import RegistrationView, LoginUserView, ForgotPasswordView, activate_user, CompletePasswordReset


urlpatterns = [
    path('login/', LoginUserView.as_view(), name="login-view"),
    path('registration/', RegistrationView.as_view(), name="registration"),
    path('password-rest/', ForgotPasswordView.as_view(), name="password-rest"),
    path('activate_user/<uid64>/<token>', activate_user, name='activate'),
    path('reset_password/<uid64>/<token>', CompletePasswordReset.as_view(), name='reset-user-password')
]