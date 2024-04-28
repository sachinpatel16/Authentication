# from django.shortcuts import render
from django.http import HttpResponse

from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import (UserRegistrationSerializers,UserLoginSerializer,
                                UserProfileSerializer,UserChangePasswordSerializer,
                                SendPasswordResetEmailSerializer,
                                UserPasswordResetSerializer)

from account.renderers import UserRenderer
from django.contrib.auth import authenticate

from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
#Gentate token manualy
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }
# Create your views here.
def home(request):
    return HttpResponse("<h1>Authentication</h1>")

class UserRegistrationView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = UserRegistrationSerializers(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({
                'status':status.HTTP_201_CREATED,
                'token':token,
                'mes':'Registration succesfully.'},status=status.HTTP_201_CREATED)
        return Response({
            'status': status.HTTP_400_BAD_REQUEST,
            'error' : serializer.errors},status=status.HTTP_400_BAD_REQUEST)

class UserLoginView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user = authenticate(email=email,password=password)
            
            if user:
                token = get_tokens_for_user(user)
                return Response({
                    'status':'201 Ok',
                    'token':token,
                    'msg':'Login Succes'},status=status.HTTP_200_OK)
            else:
                return Response({
                    'status':'404 Not Found',
                    'msg':{'non_field':['Email or passord not valid!!']}},status=status.HTTP_404_NOT_FOUND)
        return Response({'meg':'Loginsucces fully!!'})

class UserProfileView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def get(self,request,format=None):
        serializer = UserProfileSerializer(request.user)
        return Response(data=serializer.data,status=status.HTTP_200_OK)

class UserChangPasswordView(APIView):
    renderer_classes = [UserRenderer]
    permission_classes = [IsAuthenticated]
    def post(self,request,format=None):
        serializer = UserChangePasswordSerializer(data=request.data,
                                        context={'user':request.user})
        if serializer.is_valid():
            return Response({
                'status':'200 Ok',
                'msg' : "Password succesfully changed!!"},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class SendPasswordResetEmailView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,format=None):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                'status':'201 Ok',
                'msg':'Password Reset link send. Pleas check Your Email'},
                            status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)

class UserPasswordResetView(APIView):
    renderer_classes = [UserRenderer]
    def post(self,request,uid,token,format=None):
        serializer = UserPasswordResetSerializer(data = request.data,
                                context={'uid':uid,'token':token})
        if serializer.is_valid(raise_exception=True):
            return Response({'msg':'Password Reset Succesfully'},status=status.HTTP_200_OK)
        return Response(serializer.errors,status=status.HTTP_400_BAD_REQUEST)