import json
import threading
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.views import LoginView, PasswordResetView
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.core.validators import validate_email
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template.loader import render_to_string
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
# Create your views here.
from django.views import View
from auth_user import settings
from .forms import RegistrationForm, LoginUserForm, UserPasswordResetForm, ConfrimPasswordResetForm
from .models import User
from .utils import generate_token


class EmailThread(threading.Thread):
    """Simple threading class to send the email on separate thread"""

    def __init__(self, email):
        """Constructor Called to initialize the variable to start the thread"""
        self.email = email
        threading.Thread.__init__(self)

    def run(self):
        """run method to send the email on separate thread"""
        self.email.send()


def send_action_email(request, user):
    """Send Email function to end the requested user email"""

    current_site = get_current_site(request)
    email_subject = "Activate your account"
    email_body = render_to_string("activation.html", {
        'user': user,
        'domain': current_site,
        'uid': urlsafe_base64_encode(force_bytes(user.id)),
        'token': generate_token.make_token(user)
    })

    email = EmailMessage(subject=email_subject, body=email_body, from_email=settings.EMAIL_FROM_USER,
                         to=[user.email]
                         )
    EmailThread(email).start()


class ForgotPasswordView(View):
    """Inherited View class to render the post and get methods of forgot password"""

    def get(self, request):
        """"""
        form = RegistrationForm()
        return render(request, "password_reset_form.html", context={'form': form})

    def post(self, request):
        email = request.POST['email']
        form = RegistrationForm()

        current_site = get_current_site(request)
        try:
            user = User.objects.get(email=email)
        except Exception as e:
            messages.error(request, "Please enter the verified email or register yourself")
            return render(request, "password_reset_form.html", context={'form': form})

        email_contents = {
            'user': user,
            'domain': current_site.domain,
            'uid64': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': PasswordResetTokenGenerator().make_token(user)
        }

        link = reverse("reset-user-password", kwargs={
            'uid64': email_contents['uid64'],
            'token': email_contents['token']
        })

        email_subject = "Password Reset Instructions"

        reset_url = "http//" + current_site.domain + link

        email = EmailMessage(
            subject=email_subject,
            body="Hi there! Please the Click link below to reset the password \n" + reset_url +
                 "\nnoreplay@arhamsoft.com",
            from_email=settings.EMAIL_FROM_USER,
            to=[email]
        )
        EmailThread(email).start()

        messages.success(request, "we have sent you an email to reset the password")

        return render(request, "password_reset_form.html", context={'form': form})


class CompletePasswordReset(View):

    def get(self, request, uid64, token):
        return render(request, 'set-new-password.html', context={"uid64": uid64, "token": token})

    def post(self, request, uid64, token):
        password1 = request.POST.get("password1")
        password2 = request.POST.get("password2")

        if password1 != password2:
            messages.error(request, "Password Didn't Matched")
            return render(request, 'set-new-password.html', context={"uid64": uid64, "token": token})

        if len(password1) < 6:
            messages.error(request, "Password too short! Please enter the long password")
            return render(request, 'set-new-password.html', context={"uid64": uid64, "token": token})

        try:
            user_id = force_str(urlsafe_base64_decode(uid64))
            user = User.objects.get(id=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(request, "Password reset Link is invalid! Please request a new one")
                return HttpResponseRedirect(reverse('login-view'))

            user.set_password(password1)
            user.save()
            messages.success(request, "Password Reset Successfully")
            return HttpResponseRedirect(reverse('login-view'))
        except Exception as e:
            pass

        messages.info(request, "Something went wrong please try again.")
        return render(request, 'set-new-password.html', context={"uid64": uid64, "token": token})


class LoginUserView(LoginView):
    form_class = LoginUserForm
    template_name = "login.html"

    def post(self, request, *args, **kwargs):
        form = LoginUserForm(data=request.POST)
        print(form.errors)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if not user.is_email_verified:
                messages.add_message(request, messages.ERROR,
                                     "Email is not verified, please check your email inbox"
                                     )
                return render(request, "login.html", context={"form": form})
            login(request, user)
            return HttpResponse("Login Successfully")
        else:
            return render(request, "login.html", context={"form": form})


class RegistrationView(View):

    def get(self, request):
        form = RegistrationForm()
        return render(request, "registration.html", context={"form": form})

    def post(self, request):
        form = RegistrationForm(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            user = User.objects.get(username=username)
            url = reverse("login-view")
            send_action_email(request, user)
            messages.success(request, "We send you email to verify your account")
            return HttpResponseRedirect(url)

        else:
            print(form.errors)
            return render(request, "registration.html", context={"form": form})


def activate_user(request, uid64, token):
    try:
        uid = urlsafe_base64_decode(uid64)
        user = User.objects.get(id=uid)

    except Exception as e:
        user = None
        print(e)
    print(user, generate_token.check_token(user, token))
    if user and generate_token.check_token(user, token):
        user.is_email_verified = True
        user.save()

        messages.add_message(request, messages.SUCCESS, "Email Verified! you can login")
        url = reverse("login-view")
        return HttpResponseRedirect(url)

    messages.error(request, "Something Went Wrong! Please register again")
    url = reverse("registration")
    return HttpResponseRedirect(url)
