from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
import json
from .models import AppUser

# Create your views here.

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
            response = {
                'status_code': 400,
                'message': 'Bad Request [email and password are required]'
            }

        # If data is complete than doing further process
        else:
            try:
                #Hashing password before saving to database
                password = make_password(password)
                # Creating AppUser object using data recieved in api
                user = AppUser.objects.create(name=name, email=email, password=password, age=age, gender=gender, profileImg=image)
                # Saving AppUser instance to database
                user.save()

                # Crating response
                response = {
                    'status_code': 201,
                    'message': 'User Created',
                    'data': {
                        'user_id': user.id
                    }
                }

            #In case of any exception happened handling it
            except Exception as e:
                # Crating response
                response = {
                    'status_code': 400,
                    'message': f'Bad Request [{e}]'
                }
        
    # If method is not POST than returning error
    else:
        # Crating response
        response = {
            'status_code': 405,
            'message': 'Method Not Allowed'
        }
    
    # Creating json from response
    response = json.dumps(response)
    # Returning JsonResponse
    return JsonResponse(response, safe=False)



@csrf_exempt
def login(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not email or not password:
            response = {
                'status_code': 400,
                'message': 'Bad Request [email and password are required]'
            }
        
        else:
            pass


        pass


    else:
        pass
