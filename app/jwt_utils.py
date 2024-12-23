import jwt
import datetime
from django.conf import settings

def generate_jwt_token(user):
    payload = {
        'user_id': user.id,
        'email': user.email,
        'exp': (datetime.datetime.utcnow() + datetime.timedelta(days=1)).timestamp(),  # Token expires in 1 day
        'iat': datetime.datetime.utcnow().timestamp()  # Issued at time
    }
    
    # Secret key should be stored in your settings
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm='HS256')
    return token

def decode_jwt_token(token):
    payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
    return payload