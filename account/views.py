from .serializers import UserSerializer, OTPSerializer
from .utils import send_otp_email, generate_otp
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken

class OTPRequestView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            email = serializer.validated_data['email']
            username = email.split('@')[0]
            request.session['email'] = email
            request.session['username'] = username

            try:
                otp = generate_otp()
                request.session['otp'] = otp  # Store OTP in session
                send_otp_email(email, username, otp)  # Send OTP via email
                response_data = {"message": "OTP sent successfully"}
                return Response(response_data, status=status.HTTP_200_OK)
            except Exception as e:
                error_msg = str(e)
                return Response({'error': error_msg}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class OTPVerificationView(APIView):
    def post(self, request, *args, **kwargs):
        serializer = OTPSerializer(data=request.data)
        if serializer.is_valid():
            entered_otp = serializer.validated_data['otp']
            email = request.session.get('email')
            saved_otp = request.session.get('otp')
            
            # Debugging print statement
            print("Saved OTP:", saved_otp)
            print("Entered OTP:", entered_otp)

            if saved_otp is None:
                return Response({'error': 'OTP has expired or is invalid'}, status=status.HTTP_400_BAD_REQUEST)

            if entered_otp == saved_otp:
                try:
                    user = User.objects.get(email=email)
                except User.DoesNotExist:
                    username = request.session.get('username')
                    user = User.objects.create(username=username, email=email)

                refresh = RefreshToken.for_user(user)

                user_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }

                response_data = {
                    'user': user_data,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP entered'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
