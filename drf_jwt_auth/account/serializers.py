from django.forms import ValidationError
from rest_framework import serializers
from .models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from .utils import Util


class UserRegistrationSerializer(serializers.ModelSerializer):
    # This is because we need confirm password filed in our registration request
    password2 = serializers.CharField(style={'input_type': 'password'}, write_only=True)
    class Meta:
        model=User
        fields=['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password': {'write_only': True}
        }
    
    # Validating password and confirm password while registration
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        if password != password2:
            raise serializers.ValidationError("Passwords does not match !")
        return attrs
    
    # Creating user for the the custom User model
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)


class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    class Meta:
        model=User
        fields=['email', 'password']


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields=['id', 'email', 'name']
        

class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    
    class Meta:
         fields = ['password', 'password2']
    
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Passwords does not match !")
        user.set_password(password)
        user.save()
        return attrs


class SendUserPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)
    
    class Meta:
        fields = ['email']
    
    def validate(self, attrs):
        email = attrs.get('email')
        if User.objects.filter(email=email).exists():
            user = User.objects.get(email=email)
            uid = urlsafe_base64_encode(force_bytes(user.id))
            print(f"----------- encoded uid : {uid}")
            token = PasswordResetTokenGenerator().make_token(user)
            print(f"--------------- password reset token : {token}")
            link = 'http://localhost/3000/api/user/reset/'+uid+'/'+token
            print(f"--------------------- password reset link : {link}")
            
            body = 'Click following link to reset your password : '+link
            # Send email
            data = {
                'subject': 'Reset Your Password',
                'body': body,
                'to_email': user.email
            }
            Util.send_email(data)
            
            return attrs
        else:
            raise ValidationError("You are not a registered user.")
        return super().validate(attrs)


class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    password2 = serializers.CharField(max_length=255, style={'input_type': 'password'}, write_only=True)
    
    class Meta:
         fields = ['password', 'password2']

    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            uid = self.context.get('uid')
            token = self.context.get('token')
            if password != password2:
                raise serializers.ValidationError("Passwords does not match !")
            id = smart_str(urlsafe_base64_decode(uid))
            user = User.objects.get(id=id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError("Token is not valid or expired.")
            user.set_password(password)
            user.save()
            return attrs
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError("Token is not valid or expired.")