from .views import (
    OTPRequestView,
    OTPVerificationView,
    ProtectedView

)
from django.urls import path
urlpatterns = [
    path('otp-request/', OTPRequestView.as_view(), name='otp-request'),
    path('otp-verification/', OTPVerificationView.as_view(), name='otp-verification'),
    path('protected-endpoint/', ProtectedView.as_view(), name='protected-view'),
]