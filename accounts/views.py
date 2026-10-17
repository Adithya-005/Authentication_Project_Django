import logging
import secrets
import smtplib
import time

from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.shortcuts import redirect, render

from .forms import PasswordChangeOTPForm, UserForm

logger = logging.getLogger(__name__)
OTP_HASH_SESSION_KEY = "password_change_otp_hash"
OTP_EXPIRY_SESSION_KEY = "password_change_otp_expiry"
OTP_ATTEMPTS_SESSION_KEY = "password_change_otp_attempts"
OTP_LIFETIME_SECONDS = 5 * 60
OTP_MAX_ATTEMPTS = 5
VERIFIED_SESSION_KEY = "password_change_verified_until"


def signin(request):
    if request.method=='POST':
        fm=AuthenticationForm(data=request.POST)
        if fm.is_valid():
            user=fm.get_user()
            login(request,user)

            if user.email:
                try:
                    send_mail(
                        subject='Login alert',
                        message=f'Hi {user.username}, you have successfully logged in to your account.',
                        from_email=settings.DEFAULT_FROM_EMAIL,
                        recipient_list=[user.email],
                        fail_silently=False,
                    )
                except Exception:
                    logger.exception('Failed to send login email to %s', user.email)

            return redirect('home')
        context={'form':fm}
        return render(request,'signin.html',context)
    context={'form':AuthenticationForm()}
    return render(request,'signin.html',context)


def register(request):
    if request.method=='POST':
        fm=UserForm(data=request.POST)
        if fm.is_valid():
            fm.save()
            return redirect('signin')
        context={'form':fm}
        return render(request,'register.html',context)
    context={'form':UserForm()}
    return render(request,'register.html',context)

def home(request):
    return render(request,'homepage.html')

def signout(request):
    if request.method=='POST':
        logout(request)
        return redirect('signin')
    return render(request,'signout.html')


def _password_change_is_verified(request):
    verified_until = request.session.get(VERIFIED_SESSION_KEY)
    return (
        isinstance(verified_until, (int, float))
        and time.time() < verified_until
    )


def _send_password_change_otp(request):
    user = request.user
    if not user.email:
        return False

    otp = f"{secrets.randbelow(1_000_000):06d}"
    try:
        sent = send_mail(
            subject="Password change verification code",
            message=(
                f"Your password change verification code is {otp}. "
                f"It expires in {OTP_LIFETIME_SECONDS // 60} minutes."
            ),
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
    except (OSError, smtplib.SMTPException):
        logger.exception("Failed to send password-change OTP to %s", user.email)
        return False

    if sent != 1:
        logger.error("Password-change OTP email was not sent to %s", user.email)
        return False

    request.session[OTP_HASH_SESSION_KEY] = make_password(otp)
    request.session[OTP_EXPIRY_SESSION_KEY] = time.time() + OTP_LIFETIME_SECONDS
    request.session[OTP_ATTEMPTS_SESSION_KEY] = 0
    request.session.pop(VERIFIED_SESSION_KEY, None)
    return True


@login_required
def update_password(request):
    user = request.user
    if request.method == "POST" and request.POST.get("action") == "send_otp":
        if not user.email:
            return render(
                request,
                "update_password.html",
                {"otp_verified": False, "error": "Your account has no email address."},
            )
        if not _send_password_change_otp(request):
            return render(
                request,
                "update_password.html",
                {
                    "otp_verified": False,
                    "error": "We could not send the verification code. Please try again.",
                },
            )
        return redirect("verify_password_change_otp")

    if not _password_change_is_verified(request):
        request.session.pop(VERIFIED_SESSION_KEY, None)
        return render(request, "update_password.html", {"otp_verified": False})

    if request.method == "POST":
        form = PasswordChangeForm(user=user, data=request.POST)
        if form.is_valid():
            user = form.save()
            request.session.pop(VERIFIED_SESSION_KEY, None)
            update_session_auth_hash(request, user)
            return redirect("home")
    else:
        form = PasswordChangeForm(user=user)

    return render(
        request,
        "update_password.html",
        {"form": form, "otp_verified": True},
    )


@login_required
def verify_password_change_otp(request):
    if request.method == "POST":
        form = PasswordChangeOTPForm(request.POST)
        if form.is_valid():
            otp_hash = request.session.get(OTP_HASH_SESSION_KEY)
            expires_at = request.session.get(OTP_EXPIRY_SESSION_KEY)
            if (
                isinstance(otp_hash, str)
                and isinstance(expires_at, (int, float))
                and time.time() < expires_at
                and check_password(form.cleaned_data["otp"], otp_hash)
            ):
                request.session.pop(OTP_HASH_SESSION_KEY, None)
                request.session.pop(OTP_EXPIRY_SESSION_KEY, None)
                request.session.pop(OTP_ATTEMPTS_SESSION_KEY, None)
                request.session[VERIFIED_SESSION_KEY] = (
                    time.time() + OTP_LIFETIME_SECONDS
                )
                return redirect("update_password")
            if (
                isinstance(otp_hash, str)
                and isinstance(expires_at, (int, float))
                and time.time() < expires_at
            ):
                attempts = request.session.get(OTP_ATTEMPTS_SESSION_KEY, 0)
                if not isinstance(attempts, int):
                    attempts = 0
                attempts += 1
                if attempts >= OTP_MAX_ATTEMPTS:
                    request.session.pop(OTP_HASH_SESSION_KEY, None)
                    request.session.pop(OTP_EXPIRY_SESSION_KEY, None)
                    request.session.pop(OTP_ATTEMPTS_SESSION_KEY, None)
                    form.add_error(
                        "otp",
                        "Too many incorrect codes. Request a new verification code.",
                    )
                else:
                    request.session[OTP_ATTEMPTS_SESSION_KEY] = attempts
                    form.add_error("otp", "The code is invalid.")
            else:
                request.session.pop(OTP_HASH_SESSION_KEY, None)
                request.session.pop(OTP_EXPIRY_SESSION_KEY, None)
                request.session.pop(OTP_ATTEMPTS_SESSION_KEY, None)
                form.add_error("otp", "The code is invalid or expired.")
    else:
        if OTP_HASH_SESSION_KEY not in request.session:
            return redirect("update_password")
        form = PasswordChangeOTPForm()

    return render(request, "otpverify.html", {"form": form})


