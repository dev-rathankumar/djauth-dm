from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages, auth
from accounts.models import Account
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.http import HttpResponse
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required

from django.contrib.auth.hashers import check_password
from django.http import HttpResponse

# Create your views here.
def register(request):
    """User Registration"""
    if request.method == 'POST':
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            if Account.objects.filter(username=username).exists():
                messages.error(request, 'Username already exists')
                return redirect('register')
            else:
                if Account.objects.filter(email=email).exists():
                    messages.error(request, 'Email already exists')
                    return redirect('register')
                else:
                    user = Account.objects.create_user(first_name=first_name,
                    last_name=last_name, username=username, email=email, password=password)
                    user.save()
                    current_site = get_current_site(request)
                    mail_subject = 'Activate your account.'
                    message = render_to_string('accounts/acc_active_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': default_token_generator.make_token(user),
                    })
                    to_email = email
                    email = EmailMessage(
                        mail_subject, message, to=[to_email]
                    )
                    email.send()
                    messages.warning(request, 'Please confirm your email address to complete the registration')
                    return redirect('login')
        else:
            messages.error(request, 'Password do not match')
            return redirect('register')
    else:
        return render(request, 'accounts/register.html')


def activate(request, uidb64, token):
    """Activating Users"""
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account is activated.')
        return redirect('login')
    else:
        messages.error(request, 'Activation link is invalid')
        return redirect('register')

def login(request):
    """User Login"""
    if request.method == 'POST':
        email = request.POST['email']
        password = request.POST['password']

        user = auth.authenticate(email=email, password=password)

        if user is not None:
            auth.login(request, user)
            messages.success(request, 'You are now logged in.')
            return redirect('dashboard')
        if user is None:
            messages.error(request, 'Invalid login credentials')
            return redirect('login')
    return render(request, 'accounts/login.html')

@login_required(login_url = 'login')
def dashboard(request):
    return render(request, 'accounts/dashboard.html')

@login_required
def editprofile(request):
    if request.method == 'POST':
        user_id = request.POST['user_id']
        first_name = request.POST['first_name']
        last_name = request.POST['last_name']
        username = request.POST['username']
        email = request.POST['email']

        # Get exiting user data for comparision
        get_user = Account.objects.get(pk=user_id)

        if get_user.first_name != first_name or get_user.last_name != last_name or get_user.username != username or get_user.email != email:
            if get_user.username != username:
                if Account.objects.filter(username=username).exists():
                    messages.error(request, 'Username already exists')
                    return redirect('editprofile')
                else:
                    user = Account.objects.filter(pk=user_id).update(first_name=first_name, last_name=last_name, username=username)
                    messages.success(request, 'Profile updated successfully')
                    return redirect('editprofile')
            elif get_user.email != email:
                if Account.objects.filter(email=email).exists():
                    messages.error(request, 'Email already exists')
                    return redirect('editprofile')
                else:
                    user = Account.objects.filter(pk=user_id).update(first_name=first_name, last_name=last_name,
                                username=username,email=email, is_active=False)
                    # Get info and send verification email
                    current_site = get_current_site(request)
                    mail_subject = 'Activate your account.'
                    message = render_to_string('accounts/acc_active_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(get_user.pk)),
                        'token': default_token_generator.make_token(get_user),
                    })
                    to_email = email
                    email = EmailMessage(
                            mail_subject, message, to=[to_email]
                    )
                    email.send()
                    auth.logout(request)
                    messages.warning(request, 'Please verify your email address and login again.')
                    return redirect('login')
            else:
                user = Account.objects.filter(pk=user_id).update(first_name=first_name, last_name=last_name)
                messages.success(request, 'Profile updated successfully')
                return redirect('editprofile')
        else:
            return redirect('editprofile')
    return render(request, 'accounts/editprofile.html')

@login_required
def changepassword(request):
    if request.method == 'POST':
        current_password = request.POST['current_password']
        new_password = request.POST['new_password']
        confirm_password = request.POST['confirm_password']

        user = Account.objects.get(username__exact=request.user.username)
        if new_password == confirm_password:
            success = user.check_password(request.POST['current_password'])
            if success:
                user.set_password(new_password)
                user.save()
                auth.logout(request)
                messages.success(request, 'Password updated successfully')
                return redirect('login')
            else:
                messages.error(request, 'Password incorrect')
                return redirect('changepassword')
        else:
            messages.error(request, 'Password do not match!')
            return redirect('changepassword')
    else:
        return render(request, 'accounts/changepassword.html')

def logout(request):
    if request.method == 'POST':
        auth.logout(request)
        messages.success(request, 'You are logged out.')
        return redirect('login')
    return redirect('login')

def forgot_password(request):
    """Send password reset email"""
    if request.method == 'POST':
        email = request.POST['email']
        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email__exact=email)
            current_site = get_current_site(request)
            mail_subject = 'Reset Your Password'
            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })
            to_email = email
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            messages.warning(request, 'Password reset email has been sent.')
            return redirect('login')
        else:
            messages.error(request, 'Account does not exists!')
            return redirect('forgot_password')
    else:
        return render(request, 'accounts/forgot_password.html')

def resetpassword_validate(request, uidb64, token):
    """Resetting password request validation"""
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except(TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None
    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password')
        return redirect('resetpassword')
    else:
        messages.error(request, 'This link has been expired')
        return redirect('login')

def resetpassword(request):
    """Reset password"""
    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()
            messages.success(request, 'Password reset successful')
            return redirect('login')
        else:
            messages.error(request, 'Password do not match')
            return redirect('resetpassword')
    else:
        return render(request, 'accounts/resetpassword.html')
