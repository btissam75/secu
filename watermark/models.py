# watermark/models.py

import os
from uuid import uuid4

from django.db import models
from django.contrib.auth.models import User




from django.shortcuts       import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required

# (… vos autres imports, e.g. encrypt/decrypt helpers, settings, messages, etc.)

from django.db import models
from django.contrib.auth.models import User

class Document(models.Model):
    user          = models.ForeignKey(User, on_delete=models.CASCADE)
    title         = models.CharField(max_length=200)
    uploaded_file = models.FileField(upload_to='uploads/')
    uploaded_at   = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class SecureFile(models.Model):
    user      = models.ForeignKey(User, on_delete=models.CASCADE)
    name      = models.CharField(max_length=200)
    file      = models.ImageField(upload_to='stego/')
    file_type = models.CharField(max_length=20)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name

# Ajoutez ici la classe DecryptedDocument :
class DecryptedDocument(models.Model):
    user         = models.ForeignKey(User, on_delete=models.CASCADE)
    name         = models.CharField(max_length=200)
    file         = models.FileField(upload_to='decrypted/')
    decrypted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name


def user_directory_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = f"{uuid4().hex}.{ext}"
    return os.path.join('files', f'user_{instance.user.id}', filename)

class Document(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    uploaded_file = models.FileField(upload_to=user_directory_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # Champ pour savoir si le document est “sélectionné” ou non
    is_selected = models.BooleanField(default=False)

    def __str__(self):
        return self.title
def user_directory_path(instance, filename):
    """
    Génère un chemin unique pour stocker les fichiers par utilisateur.
    Exemple : files/user_4/3f1e2d4c5b6a.jpg
    """
    ext = filename.split('.')[-1]
    filename = f"{uuid4().hex}.{ext}"
    return os.path.join('files', f'user_{instance.user.id}', filename)


class Document(models.Model):
    """
    Modèle pour stocker les documents uploadés par l'utilisateur.
    - `is_selected` permet de marquer le document comme sélectionné.
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    uploaded_file = models.FileField(upload_to=user_directory_path)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_selected = models.BooleanField(default=False)

    def __str__(self):
        return self.title




class SecureFile(models.Model):
    """
    Modèle pour gérer les fichiers « sécurisés » (chiffrés/steganographiés, etc.).
    - `icon` stocke le nom de l'icône associé (dans static/icons/).
    """
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='secure_files/')
    file_type = models.CharField(max_length=10)
    icon = models.CharField(max_length=50, default='default.png')

    def __str__(self):
        return self.name


class Order(models.Model):
    """
    Modèle pour gérer des commandes ou des opérations (ex. historique).
    """
    name = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
from django.db import models
from django.contrib.auth.models import User


class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    bio  = models.TextField(blank=True)
    # … autres champs (photo, 2FA, etc.) …

    def __str__(self):
        return f"Profil de {self.user.username}"



