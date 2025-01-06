import jwt
from django.conf import settings
from django.http import JsonResponse
from .models import BlockedToken

# Decorator to check JWT token validity without using functools.wraps
def jwt_required(view_func):
    def _wrapped_view(request, *args, **kwargs):
        # Extract JWT token from HttpOnly cookie
        token = request.COOKIES.get('jwt_token')

        if not token:
            return JsonResponse({
                'status_code': 400,
                'message': 'Bad Request [Authorization token in HttpOnly cookie is required]'
            }, status=400)

        # Looking into database if token is saved in BlockedToken token
        token_inBlocked = list(BlockedToken.objects.filter(value=token))
        if(len(token_inBlocked) != 0):
            return JsonResponse({
                'status_code': 401,
                'message': 'Unauthorized [Token has expired]'
            }, status=401)

        try:
            # Decode the JWT token to get the payload
            payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=['HS256'])
            # Optionally, add the decoded payload to the request object for access in the view
            request.user = payload  # Storing the decoded payload in request.user for further use (e.g., user id)
        except jwt.ExpiredSignatureError:
            return JsonResponse({
                'status_code': 401,
                'message': 'Unauthorized [Token has expired]'
            }, status=401)
        except jwt.InvalidTokenError:
            return JsonResponse({
                'status_code': 401,
                'message': 'Unauthorized [Invalid token]'
            }, status=401)

        # Proceed to the view if token is valid
        return view_func(request, *args, **kwargs)

    # Return the wrapper function
    return _wrapped_view
