import jwt
import datetime
from django.conf import settings

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': datetime.datetime.now() + datetime.timedelta(minutes=10),  # Token expires in 10 minutes
        'iat': datetime.datetime.now()  # Issued at time
    }
    
    # Secret key should be stored in your settings
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt_token(token):
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
    return payload