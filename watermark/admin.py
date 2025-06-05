from django.contrib import admin
from django.contrib.auth.models import User
from django.contrib.auth.admin import UserAdmin
from .models import Profile

admin.site.register(Profile)

from .models import Document

admin.site.register(Document)

# Personnaliser l'affichage des colonnes dans l'admin
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'email', 'first_name', 'last_name', 'is_staff', 'is_active')

# Désenregistrer l'ancien UserAdmin et enregistrer le nouveau
admin.site.unregister(User)
admin.site.register(User, CustomUserAdmin)

# Register your models here.
