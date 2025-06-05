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
