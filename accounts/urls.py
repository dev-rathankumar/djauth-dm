from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('', views.dashboard, name='dashboard'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('editprofile/', views.editprofile, name='editprofile'),
    path('changepassword/', views.changepassword, name='changepassword'),
    path('forgot_password/', views.forgot_password, name='forgot_password'),
    path('resetpassword_validate/<uidb64>/<token>/', views.resetpassword_validate, name='resetpassword_validate'),
    path('logout', views.logout, name='logout'),
    path('activate/<uidb64>/<token>/', views.activate, name='activate'),
    path('resetpassword/', views.resetpassword, name='resetpassword')
]
