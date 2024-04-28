from django.urls import path
from account import views

# from rest_framework_simplejwt.views import (
#     TokenObtainSlidingView,
#     TokenRefreshSlidingView,
# )

urlpatterns = [
    path("user/register/",views.UserRegistrationView.as_view(),name='user-reg'),
    path("user/login/",views.UserLoginView.as_view(),name='user-login'),
    path("user/profile/",views.UserProfileView.as_view(),name='user-profile'),
    path("user/changePassword/",views.UserChangPasswordView.as_view(),name='user-profile'),
    path("user/reset/",views.SendPasswordResetEmailView.as_view(),name='user-reset'),
    path("user/reset/<uid>/<token>/",views.UserPasswordResetView.as_view(),name='user-reset-view'),
    # path("user/reset/ob/",TokenObtainSlidingView.as_view(),name='user-reset-view'),
    # path("user/reset/ref/",TokenRefreshSlidingView.as_view(),name='user-reset-view'),
]
