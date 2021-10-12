from django.urls import path, include
from django.urls import reverse_lazy
from django.contrib.auth.views import (
    LoginView,
    LogoutView,
    PasswordChangeView,
    PasswordChangeDoneView,
    PasswordResetView,
    PasswordResetDoneView,
    PasswordResetConfirmView,
    PasswordResetCompleteView,
)
from authentication.views import (
    APIMeView,
    APILoginView,
    APILogoutView,
    APIPasswordResetView,
    APIPasswordResetConfirmView,
    APIUserRegister,
)
from django.contrib.auth.decorators import login_required
from django.views.generic import TemplateView
from rest_framework_simplejwt.views import (TokenObtainPairView,
                                            TokenRefreshView,
                                            TokenVerifyView)


urlpatterns = [
    path('login', LoginView.as_view(template_name="auth.login.html"),
         name='auth_login'),
    path('logout', LogoutView.as_view(next_page='/'), name='auth_logout'),
    path('', login_required(TemplateView.as_view(template_name="auth.main.html")),
         name='auth_main'),

    # Views to change password as logged-in
    path('password_change/', PasswordChangeView.as_view(), name='auth_password_change'),
    path('password_change/done/', PasswordChangeDoneView.as_view(), name='auth_password_change_done'),

    # Views to reset a password.
    path('password_reset/',
         PasswordResetView.as_view(
             email_template_name='auth.password_reset_email.html',
             template_name='auth.password_reset_form.html',
             success_url=reverse_lazy('auth_password_reset_done')
         ),
         name='auth_password_reset'),
    path('password_reset/done/',
         PasswordResetDoneView.as_view(template_name='auth.password_reset_done.html'),
         name='auth_password_reset_done'),
    path('reset/<uidb64>/<token>/',
         PasswordResetConfirmView.as_view(
             template_name='auth.password_reset_confirm.html',
             success_url=reverse_lazy('auth_password_reset_complete')
         ),
         name='auth_password_reset_confirm'),
    path('reset/done/',
         PasswordResetCompleteView.as_view(template_name='auth.password_reset_complete.html'),
         name='auth_password_reset_complete'),

    path('me/', APIMeView.as_view(), name='api_me'),
    path('login/', APILoginView.as_view(), name='api_login'),
    path('logout/', APILogoutView.as_view(), name='api_logout'),

    path('token/', TokenObtainPairView.as_view(),
         name='token_obtain_pair'),
    path('token/refresh/', TokenRefreshView.as_view(),
         name='token_refresh'),
    path('token/verify/', TokenVerifyView.as_view(),
         name='token_verify'),

    path('password_reset',
         APIPasswordResetView.as_view(),
         name='api_password_reset'),
    path('reset/<uidb64>/<token>/',
         APIPasswordResetConfirmView.as_view(),
         name='api_password_reset_confirm'),
     
     path('register',
          APIUserRegister.as_view(),
          name="api_user_register"),
]