from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User
from django.forms import ModelForm
from .models import Order




class CreateNewUser(UserCreationForm):
    email = forms.EmailField(required=True, label="Adresse email")

    class Meta:
        model = User
        fields = ['username', 'email', 'password1', 'password2']


# watermark/forms.py

from django import forms
from django.conf import settings
# watermark/forms.py
from django import forms

# watermark/forms.py

from django import forms
from django.contrib.auth import get_user_model

User = get_user_model()

class RegisterForm(forms.Form):
    username  = forms.CharField(max_length=150)
    email     = forms.EmailField()
    password1 = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(widget=forms.PasswordInput)

    def clean_username(self):
        username = self.cleaned_data['username']
        if User.objects.filter(username=username).exists():
            raise forms.ValidationError("Ce nom d’utilisateur est déjà pris.")
        return username

    def clean_email(self):
        email = self.cleaned_data['email']
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError("Cette adresse email est déjà utilisée.")
        return email

    def clean(self):
        cleaned_data = super().clean()
        pwd1 = cleaned_data.get('password1')
        pwd2 = cleaned_data.get('password2')
        if pwd1 and pwd2 and pwd1 != pwd2:
            raise forms.ValidationError("Les mots de passe ne correspondent pas.")
        return cleaned_data


User = settings.AUTH_USER_MODEL

# class MessageForm(forms.ModelForm):
#     recipient = forms.ModelChoiceField(
#         queryset=None,
#         label="Destinataire",
#         widget=forms.Select(attrs={'class': 'form-select'})
#     )
#     subject = forms.CharField(
#         max_length=200,
#         required=False,
#         label="Objet",
#         widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Objet du message (facultatif)'})
#     )
#     body = forms.CharField(
#         label="Contenu",
#         widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 6, 'placeholder': 'Écrivez votre message ici...'})
#     )

#     class Meta:
#         model = Message
#         fields = ['recipient', 'subject', 'body']

#     def __init__(self, *args, **kwargs):
#         user = kwargs.pop('user')  # On passera l'utilisateur connecté en paramètre
#         super().__init__(*args, **kwargs)
#         # On ne veut pas que l’utilisateur s’envoie un message à lui-même, donc on exclut self
#         self.fields['recipient'].queryset = settings.AUTH_USER_MODEL.objects.exclude(id=user.id)
