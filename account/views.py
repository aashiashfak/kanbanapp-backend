from .serializers import UserSerializer, OTPSerializer
from .utils import send_otp_email, generate_otp
from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.contrib.auth.models import User
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

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
                print('generated otp :', otp)
                request.session['otp'] = otp  # Store OTP in session
                session_otp =  request.session['otp']   # Store OTP in session
                print('saved otp while email senting',session_otp)
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

                

                response_data = {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email,
                    'access_token': str(refresh.access_token),
                    'refresh_token': str(refresh),
                }
                return Response(response_data, status=status.HTTP_200_OK)
            else:
                return Response({'error': 'Invalid OTP entered'}, status=status.HTTP_400_BAD_REQUEST)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        
class ProtectedView(APIView):
    permission_classes=[IsAuthenticated]

    def get(self, request, *args, **kwargs):
        return Response({"message": "Token is valid"})
