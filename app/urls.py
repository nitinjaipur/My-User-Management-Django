from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout, name='logout'),
    path('get_user_details/', views.get_user_details, name='get_user_details'),
    path('delete_current_user/', views.delete_current_user, name='delete_current_user'),
    path('update_user/', views.update_user, name='update_user'),
    path('update_user_image/', views.update_user_image, name='update_user_image'),
]
