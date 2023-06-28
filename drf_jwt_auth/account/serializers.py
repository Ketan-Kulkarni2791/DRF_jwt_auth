from rest_framework import serializers
# from account.views import UserRegistrationView
from .models import User


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