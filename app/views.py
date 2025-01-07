from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
import json
from .models import AppUser, BlockedToken
from .jwt_utils import generate_jwt_token, decode_jwt_token
import jwt
import datetime
from django.conf import settings
from .decorators import jwt_required
import base64
from .utils import IMG_TYPE
from django.middleware.csrf import get_token

# View for User Register
@csrf_exempt
def register(request):
    # For POST method
    if(request.method == 'POST'):
        # Extracting data from form data in POST api
        name = request.POST.get('name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        age = request.POST.get('age')
        gender = request.POST.get('gender')
        image = request.FILES.get('image')

        # If data do not have email and password than return error with code 400
        if not email or not password:
            # Crating response
            status = 400
            response = {
                'status_code': 400,
                'message': 'Bad Request [email and password are required]'
            }

        # If data is complete than doing further process
        else:
            try:
                # Hashing password before saving to database
                password = make_password(password)
                # Creating AppUser object using data recieved in api
                user = AppUser.objects.create(name=name, email=email, password=password, age=age, gender=gender, profileImg=image)
                # Saving AppUser instance to database
                user.save()

                # Generating jwt token
                token = generate_jwt_token(user)

                # Crating response
                status = 201
                response = {
                    'status_code': 201,
                    'message': 'User Created',
                    'token': token
                }

            #In case of any exception happened handling it
            except Exception as e:
                # Crating response
                status = 400
                response = {
                    'status_code': 400,
                    'message': f'Bad Request [{e}]'
                }
        
    # If method is not POST than returning error
    else:
        # Crating response
        status = 404
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    
    # Returning JsonResponse
    # return JsonResponse(response, status=status, safe=False)

    response = JsonResponse(response, status=status, safe=False)
    if status == 201:
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
        response.set_cookie(
            key='jwt_token',
            value=token,
            httponly=True,  # Ensures that the cookie is inaccessible to JavaScript
            secure=True,    # Only send cookie over HTTPS (ensure your site uses HTTPS)
            samesite='Strict',  # Prevent CSRF by limiting cross-site requests
            expires=expires  # Set the expiration time
        )

        # Generate a CSRF token and set it in a cookie
        csrf_token = get_token(request)
        response.set_cookie(
            key='csrftoken',
            value=csrf_token,
            httponly=False,  # Allow JavaScript to access the cookie for client-side handling
            secure=True,     # Only send cookie over HTTPS
            samesite='Strict',  # Prevent cross-site requests
            expires=expires  # Set the expiration time
        )
    
    return response


# View for User Login
@csrf_exempt
def login(request):
    # For POST method
    if request.method == 'POST':
        # Extracting data from json data in POST api
        data = request.body
        data = json.loads(data)
        email = data.get('email')
        password = data.get('password')

        # If data do not have email and password than return error with code 400
        if not email or not password:
            status = 400
            response = {
                'status_code': 400,
                'message': 'Bad Request [email and password are required]'
            }
        
        # If data is complete than doing further process
        else:
            # Query database to find AppUser for same email
            user = AppUser.objects.filter(email=email).first()
            # If user not exist than returning response
            if not user:
                status = 404
                response = {
                    'status_code': 404,
                    'message': 'User not found'
                }
            # If user found than doing further process
            else:
                # If user password (after unhashing) and api password matches
                if check_password(password, user.password):
                    user_details = {
                        'id': user.id,
                        'name': user.name,
                        'email': user.email,
                        'age': user.age,
                        'gender': user.gender
                    }
                    if user.profileImg:
                        # Getting image type from image path
                        profileImgType = (user.profileImg.path).split('.')[-1]
                        # Getting mime type from image type
                        mime_type = IMG_TYPE.get(profileImgType)
                        image_path = user.profileImg.path
                        with open(image_path, 'rb') as img_file:
                            # Encode the image to base64
                            image_data = base64.b64encode(img_file.read()).decode('utf-8')
                            # Add the image data to the user data dictionary
                            user_details['image_data'] = f"data:{mime_type};base64,{image_data}"

                    token = generate_jwt_token(user)
                    status = 200
                    response = {
                        'status_code': 200,
                        'message': 'User found Successfully',
                        'data': user_details
                    }
                # If user password and hashed api password not matches
                else:
                    status = 401
                    response = {
                        'status_code': 401,
                        'message': 'Unauthorized'
                    }

    # If method is not POST than returning error
    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    
    # Returning JsonResponse
    # return JsonResponse(response, status=status, safe=False)
    response = JsonResponse(response, status=status, safe=False)
    if status == 200:
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
        response.set_cookie(
            key='jwt_token',
            value=token,
            httponly=True,  # Ensures that the cookie is inaccessible to JavaScript
            secure=True,    # Only send cookie over HTTPS (ensure your site uses HTTPS)
            samesite='Strict',  # Prevent CSRF by limiting cross-site requests
            expires=expires  # Set the expiration time
        )

        # Generate a CSRF token and set it in a cookie
        csrf_token = get_token(request)
        response.set_cookie(
            key='csrftoken',
            value=csrf_token,
            httponly=False,  # Allow JavaScript to access the cookie for client-side handling
            secure=True,     # Only send cookie over HTTPS
            samesite='Strict',  # Prevent cross-site requests
            expires=expires  # Set the expiration time
        )
    
    return response


# View for User Logout
@csrf_exempt
def logout(request):
    if request.method == 'POST':
        # Extract the JWT token from HttpOnly cookie
        token = request.COOKIES.get('jwt_token')

        # If it do not have have token and bearer
        if not token:
            status = 400
            response = {
                'status_code': 400,
                'message': 'Bad Request [No Authorization token in HttpOnly cookie]'
            }
        # If it do not have have token and bearer
        expire_time = datetime.datetime.utcnow().timestamp()
        expire_time = datetime.datetime.utcfromtimestamp(expire_time)
        try:
            blockedToken = BlockedToken.objects.create(value=token, expire_time=expire_time)
            blockedToken.save()

            status = 200
            response = {
                'status_code': 200,
                'message': 'Logout successfull'
            }
        # Exception if token expired
        except jwt.ExpiredSignatureError:
            status = 401
            response = {
                'status_code': 401,
                'message': 'Unauthorized [Token has expired]'
            }
        # Exception if token invalid
        except jwt.InvalidTokenError:
            status = 401
            response = {
                'status_code': 401,
                'message': 'Unauthorized [Invalid token]'
            }

    # If method is not POST than returning error
    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    # Returning JsonResponse
    # return JsonResponse(response, status=status, safe=False)
    response = JsonResponse(response, status=status, safe=False)
    if status != 405:
        response.delete_cookie('jwt_token', path='/')
        response.delete_cookie('csrftoken', path='/')
    return response


@jwt_required
def get_user_details(request):
    # Extracting user from request (setted by jwt_required decorator)
    user = request.user
    # Query to get App user from database
    user = AppUser.objects.filter(id=user['user_id']).first()

    if user:
        status = 200
        response = {
            'name': user.name,
            'email': user.email,
            'age': user.age,
            'gender': user.gender
        }

        if user.profileImg:
            # Getting image type from image path
            profileImgType = (user.profileImg.path).split('.')[-1]
            # Getting mime type from image type
            mime_type = IMG_TYPE.get(profileImgType)
            # Converting image to base64 so can be sent in json response
            image_path = user.profileImg.path
            with open(image_path, 'rb') as img_file:
                # Encode the image to base64
                image_data = base64.b64encode(img_file.read()).decode('utf-8')
                # Add the image data to the user data dictionary
                response['image_data'] = f"data:{mime_type};base64,{image_data}"
    
    else:
        status = 404
        response = {
            'status_code': 404,
            'message': 'User not found'
        }

    return JsonResponse(response, status=status, safe=False)
