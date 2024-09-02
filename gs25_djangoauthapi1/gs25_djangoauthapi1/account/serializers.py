from rest_framework import serializers
from account.models import User
from django.utils.encoding import smart_str, force_bytes, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from rest_framework.exceptions import ValidationError
from account.utils import Util




# User Registration Serializer.
class UserRegistrationSerializer(serializers.ModelSerializer):
    # We are writing this becoz we need confirm password field in our Registration Request
    password2 = serializers.CharField(style={'input_type':'password'}, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'name', 'password', 'password2', 'tc']
        extra_kwargs = {
            'password':{'write_only' : True}
        }
        
        # validation password and Confirm password while Registration.
    def validate(self, data):
        password = data.get('password')
        password2 = data.get('password2')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        return data
        
        
        # Create object for registration.
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user
    
    
    
# User Login Serializer.
class UserLoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length = 100)
    class Meta:
       model = User
       fields = ['email', 'password']
       
       
# User Profile.
class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'email', 'name', 'tc']
         
         
         
# User Change Password Serializer.
class UserChangePasswordSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 100, style={'input_type':'password'},
                write_only = True)
    password2 = serializers.CharField(max_length = 100, style = {'input_type':'password'},
                write_only = True)
    class Meta:
        fields = ['password', 'password2']
        
    # validetor.
    def validate(self, attrs):
        password = attrs.get('password')
        password2 = attrs.get('password2')
        user = self.context.get('user')
        if password != password2:
            raise serializers.ValidationError("Password and Confirm Password doesn't match")
        user.set_password(password)
        user.save()
        return attrs    
       
       
# Send Email to Reset Password serializer.
class SendPasswordResetEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length = 100)
    class Meta:
        fields = ['email']
        
        
    # Validation.
    def validate(self, attrs):
       email = attrs.get('email') 
       if User.objects.filter(email = email).exists():
           user = User.objects.get(email = email)
           user_id = urlsafe_base64_encode(force_bytes(user.id))
           print('encoded UID', user_id)
           token = PasswordResetTokenGenerator().make_token(user)
           print('token Reset Token', token)
           link = 'http://localhost:3000/api/user/reset/'+user_id+'/'+token
           print('Password Reset Link', link)
           # send Email.
           body = 'Click Following link to Reset Your Password'+link
           data = {
               'subject': 'Reset your Password',
               'body': body,
               'to_email': user.email
           }
           #print("data show = ",data)
           Util.send_email(data)
           return attrs
       else:
           raise ValidationError('You are not a Registration User')
       
       
       
# User Reset Password serializer.
class UserPasswordResetSerializer(serializers.Serializer):
    password = serializers.CharField(max_length = 100, style={'input_type':'password'},
                write_only = True)
    password2 = serializers.CharField(max_length = 100, style = {'input_type':'password'},
                write_only = True)
    class Meta:
        fields = ['password', 'password2']
        
    # validetor.
    def validate(self, attrs):
        try:
            password = attrs.get('password')
            password2 = attrs.get('password2')
            user_id = self.context.get('user_id')
            token = self.context.get('token')

            if password != password2:
                raise serializers.ValidationError("Password and Confirm Password doesn't match")
            id = smart_str(urlsafe_base64_decode(user_id))
            user = User.objects.get(id = id)
            if not PasswordResetTokenGenerator().check_token(user, token):
                raise ValidationError('Token is not Valid or Expired')
            user.set_password(password)
            user.save()
            return attrs  
        except DjangoUnicodeDecodeError as identifier:
            PasswordResetTokenGenerator().check_token(user, token)
            raise ValidationError('Token is not Valid or Expired')  












