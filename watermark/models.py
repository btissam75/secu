from django.db import models
from django.contrib.auth.models import User
# watermark/models.py
from django.contrib.auth.models import User
from django.db import models

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    profile_pic = models.ImageField(upload_to='profile_pics/', default='profile_pics/default.jpg')

    def __str__(self):
        return f"Profil de {self.user.username}"


class SecureFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='secure_files/')
    file_type = models.CharField(max_length=10)
    icon = models.CharField(max_length=50, default='default.png')  # Chemin de l'icône dans static/icons

    def __str__(self):
        return self.name

class Order(models.Model):
    name = models.CharField(max_length=100)
    date_created = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.name
