from rest_framework import serializers
from account.models import User
from account.utils import Util

from django.utils.encoding import smart_str,force_bytes,DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode,urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator

#Registration
class UserRegistrationSerializers(serializers.ModelSerializer):
    # we write this because we neeed password2 filed in registration form 
    password2 = serializers.CharField(style={'input_type':'password'},write_only=True)
    class Meta:
        model = User
        fields = ['name','email','tc','password','password2']
        extra_kwargs ={
            'password':{'write_only':True}
        }
    #Validation conform Password logic
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        
        if password != password2:
            raise serializers.ValidationError("Password and Conform Password doesn't match!!")
        return attrs
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)

#Login
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=255)
    class Meta:
        model = User
        fields = ['email','password']

#Profile
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields =['id','name','email']

#Changpassword
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style=
                    {'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style=
                    {'input_type':'password'},write_only=True)
    class Meta:
        fields=['password','password2']
    
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match!!")
        user.set_password(password)
        user.save()
        return attrs

#Send messege via Email
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email = email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print("Encoded uid: ",uid)
            token = PasswordResetTokenGenerator().make_token(user)
            print("Password reset token:",token)
            link = 'http://127.0.0.1:8000/account/api/user/reset/' + uid + '/' + token
            print("Password Reset Link",link)
            #Sent Email
            body = 'Click Following Link to reset Passsword ' + link
            data = {
                'subject':'Reset Your Password',
                'body':body,
                'to_email':user.email
            }
            Util.send_mail(data)
            
            return attrs
        else:
            raise serializers.ValidationError('You are not a Register User!!')

class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style=
                    {'input_type':'password'},write_only=True)
    password2 = serializers.CharField(max_length=255, style=
                    {'input_type':'password'},write_only=True)
    class Meta:
        fields=['password','password2']
    
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            
            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match!!")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user,token):
                raise serializers.ValidationError("Token is not Valide or Expier")
            
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user,token)
            raise serializers.ValidationError("Token is not Valide or Expier")