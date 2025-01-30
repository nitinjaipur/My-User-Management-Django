from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password, check_password
import json
from .models import AppUser, BlockedToken
from .jwt_utils import generate_jwt_token, decode_jwt_token
import jwt
import datetime
from .decorators import jwt_required
from .utils import fetch_user_details
from django.middleware.csrf import get_token
from django.core.files.storage import default_storage

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
                user_details = fetch_user_details(user)
                response = {
                    'status_code': 201,
                    'message': 'User Created',
                    'data': user_details
                }

            # In case of any exception happened handling it
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
            httponly=False,  # Making it accessible to JavaScript for CSRF protection
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
                    user_details = fetch_user_details(user)
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
            httponly=False,  # Making it accessible to JavaScript for CSRF protection
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
        # If it do have have token and bearer
        else:
            expire_time = datetime.datetime.utcnow().timestamp()
            expire_time = datetime.datetime.utcfromtimestamp(expire_time)
            try:
                user = decode_jwt_token(token)
                user = AppUser.objects.filter(id=user['user_id']).first()
                blockedToken = BlockedToken.objects.create(user=user, value=token, expire_time=expire_time)
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
    response = JsonResponse(response, status=status, safe=False)
    if status != 405:
        response.delete_cookie('jwt_token', path='/')
        response.delete_cookie('csrftoken', path='/')
    return response


@jwt_required
def get_user_details(request):
    if request.method == 'GET':
        # Extracting user from request (setted by jwt_required decorator)
        user_request = request.user
        # Query to get App user from database
        user = AppUser.objects.filter(id=user_request['user_id']).first()
        if user:
            status = 200
            response = fetch_user_details(user)
        else:
            status = 404
            response = {
                'status_code': 404,
                'message': 'User not found'
            }
    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    return JsonResponse(response, status=status, safe=False)

@jwt_required
def delete_current_user(request):
    if request.method == 'DELETE':
        # Extracting user from request
        user_request = request.user
        # Query to get App user from database
        user = AppUser.objects.filter(id=user_request['user_id']).first()
        if user:
            # Deleting all BlockedToken from database related to this user
            user.blocked_tokens.all().delete()
            # Check if the user has an image
            if user.profileImg:
                # Delete the image from the storage folder
                default_storage.delete(user.profileImg.path)
            # Deleting user from database
            user.delete()
            # Setting status
            status = 200
            # Creating response data
            response = {
                'status_code': 200,
                'message': 'User deletd successfully'
            }
            # Creating response object
            response = JsonResponse(response, status=status, safe=False)
            # Deleting all the cookies from client side
            response.delete_cookie('jwt_token', path='/')
            response.delete_cookie('csrftoken', path='/')
            return response
        else:
            status = 404
            response = {
                'status_code': 404,
                'message': 'User not found'
            }
    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    response = JsonResponse(response, status=status, safe=False)
    return response


@jwt_required
def update_user(request):
    if request.method == 'PATCH':
        # Extracting user from request
        user_request = request.user
        # Query to get App user from database
        user = AppUser.objects.filter(id=user_request['user_id']).first()
        if user:
            # Extracting data from request body
            data = json.loads(request.body)
            # Storing old email
            old_email = user.email
            # Setting data to user object
            user.name = data.get('name') or user.name
            user.email = data.get('email') or user.email
            user.age = data.get('age') or user.age
            user.gender = data.get('gender') or user.gender
            # Saving user object to database
            user.save()
            # Setting status
            status = 200
            # Creating user details dictionary
            user_details = fetch_user_details(user)
            # Creating response data
            response = {
                'status_code': 200,
                'message': 'User updated successfully',
                'data': user_details
            }

    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    # Creating response object
    response = JsonResponse(response, status=status, safe=False)
    # Updating jwt token with new details if email is updated
    if status == 200 and old_email != user.email:
        token = generate_jwt_token(user)
        expires = datetime.datetime.utcnow() + datetime.timedelta(days=1)  # Token expires in 1 day
        response.set_cookie(
            key='jwt_token',
            value=token,
            httponly=True,  # Ensures that the cookie is inaccessible to JavaScript
            secure=True,    # Only send cookie over HTTPS (ensure your site uses HTTPS)
            samesite='Strict',  # Prevent CSRF by limiting cross-site requests
            expires=expires  # Set the expiration time
        )

    return response

@jwt_required
def update_user_image(request):
    if request.method == 'POST':
        # Extracting user from request
        user_request = request.user
        # Query to get App user from database
        user = AppUser.objects.filter(id=user_request['user_id']).first()
        if user:
            # Check if the user already has an image
            if user.profileImg:
                # Delete the old image from the storage folder
                default_storage.delete(user.profileImg.path)
            # Save the new image to the storage folder
            user.profileImg = request.FILES.get('image')
            # Save the user object to the database
            user.save()
            # Setting status
            status = 200
            # Creating user details dictionary
            user_details = fetch_user_details(user)
            # Creating response data
            response = {
                'status_code': 200,
                'message': 'User updated successfully',
                'data': user_details
            }
    else:
        status = 405
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    response = JsonResponse(response, status=status, safe=False)
    return response
