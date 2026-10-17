from django.urls import path
from . import views
from django.contrib.auth.decorators import login_required


urlpatterns = [
    path('register/', views.register, name='register'),
    path('signin/', views.signin, name='signin'),
    path('home/', login_required(views.home), name='home'),
    path('signout/', login_required(views.signout), name='signout'),
    path('update-password/', login_required(views.update_password), name='update_password'),
    path(
        'update-password/verify/',
        login_required(views.verify_password_change_otp),
        name='verify_password_change_otp',
    ),
]