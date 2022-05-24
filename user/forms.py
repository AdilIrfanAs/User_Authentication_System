from django import forms
from django.contrib.auth import password_validation
from django.contrib.auth.forms import UsernameField, AuthenticationForm, PasswordResetForm
from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import User

from user.models import User


class RegistrationForm(forms.ModelForm):
    """
    A form that creates a user, with no privileges, from the given username and
    password.
    """

    error_messages = {
        "password_mismatch": _("The two password fields didn’t match."),
    }
    first_name = forms.CharField(
        widget=forms.TextInput(attrs={
            "required": "True",
            "name": "firstname",
            "id": "firstname",
            "type": "text",
            "placeholder": "Firstname"
        })
    )
    last_name = forms.CharField(
        widget=forms.TextInput(attrs={
            "required": "True",
            "name": "lastname",
            "id": "lastname",
            "type": "text",
            "placeholder": "Lastname"
        })
    )
    username = forms.CharField(
        widget=forms.TextInput(attrs={
            "required": "True",
            "name": "username",
            "id": "username",
            "type": "text",
            "placeholder": "Username"
        })
    )
    email = forms.EmailField(
        label=_("Password confirmation"),
        widget=forms.TextInput(attrs={
            "required": "True",
            "name": "email",
            "id": "email",
            "type": "email",
            "placeholder": "Email"
        }),
    )
    password1 = forms.CharField(
        label=_("Password"),
        strip=False,
        widget=forms.PasswordInput(attrs={
            "autocomplete": "new-password",
            "required": "True",
            "name": "password",
            "id": "password",
            "type": "password",
            "placeholder": "Password"
        }),
        help_text=password_validation.password_validators_help_text_html(),
    )
    password2 = forms.CharField(
        label=_("Password confirmation"),
        widget=forms.PasswordInput(attrs={
            "autocomplete": "new-password",
            "required": "True",
            "name": "confirm_password",
            "id": "confirm_password",
            "type": "password",
            "placeholder": "Confirm Password"
        }),
        strip=False,
        help_text=_("Enter the same password as before, for verification."),
    )

    class Meta:
        model = User
        fields = ("first_name", "last_name", "email", "username", "password1", "password2")
        field_classes = {"username": UsernameField}

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if self._meta.model.USERNAME_FIELD in self.fields:
            self.fields[self._meta.model.USERNAME_FIELD].widget.attrs[
                "autofocus"
            ] = True

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email__contains=email).exists():
            raise ValidationError('Email Already Exists')
        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise ValidationError(
                self.error_messages["password_mismatch"],
                code="password_mismatch",
            )
        return password2

    def _post_clean(self):
        super()._post_clean()
        # Validate the password after self.instance is updated with form data
        # by super().
        password = self.cleaned_data.get("password2")
        if password:
            try:
                password_validation.validate_password(password, self.instance)
            except ValidationError as error:
                self.add_error("password2", error)

    def save(self, commit=True):
        user = super().save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user


class LoginUserForm(AuthenticationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].widget.attrs.update({
            "required": "True",
            "name": "username",
            "type": "text",
            "id": "username",
            "placeholder": "Username"
        })
        self.fields['password'].widget.attrs.update({
            "required": "True",
            "name": "password",
            "type": "password",
            "id": "password",
            "placeholder": "Password"
        })

    class Meta:
        model = User
        fields = ["username", "password"]


class UserPasswordResetForm(PasswordResetForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['email'].widget.attrs.update({
            "required": "True",
            "name": "email",
            "type": "email",
            "id": "email",
            "placeholder": "Email"
        })

    class Meta:
        model = User
        fields = ["email"]

class ConfrimPasswordResetForm(PasswordResetForm):
    def __int__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password'].widget.attrs.update({
            "required": "True",
            "name": "password1",
            "type": "password",
            "id": "password1",
            "placeholder": "Password"
        })
        self.fields['password2'].widget.attrs.update({
            "required": "True",
            "name": "password2",
            "type": "password",
            "id": "password2",
            "placeholder": "Confirm Password"
        })

    class Meta:
        model = User
        fields = ['password', 'password2']