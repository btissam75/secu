from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.contrib import messages
from .forms import CreateNewUser
from .models import SecureFile

#===========================================btissam=======================================================



def account_view(request):
    return render(request, 'watermark/profile.html')  # ou settings.html

# ✅ Page principale (Login)
def login_view(request):
    if request.method == 'POST':
        identifiant = request.POST.get('username')
        password = request.POST.get('password')
        if '@' in identifiant:
            try:
                user_obj = User.objects.get(email=identifiant)
                username = user_obj.username
            except User.DoesNotExist:
                messages.error(request, "Email introuvable.")
                return redirect('login')
        else:
            username = identifiant
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('dashboard')
        else:
            messages.error(request, "Identifiants incorrects.")
            return redirect('login')
    return render(request, 'watermark/login.html')

# ✅ Logout
def userLogout(request):
    logout(request)
    return redirect('home')

# ✅ Register
def register(request):
    if request.method == 'POST':
        form = CreateNewUser(request.POST)
        if form.is_valid():
            form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f"Le compte {username} a été créé avec succès !")
            return redirect('login')
        else:
            messages.error(request, "Erreur dans le formulaire. Veuillez corriger.")
    else:
        form = CreateNewUser()
    return render(request, 'watermark/register.html', {'form': form})

# ✅ Dashboard
@login_required
def dashboard(request):
    return render(request, 'watermark/dashboard.html')

# ✅ Upload document
@login_required
def upload_document(request):
    if request.method == 'POST' and request.FILES.get('document'):
        fichier = request.FILES['document']
        # Traitement possible ici...
        messages.success(request, f"Le fichier {fichier.name} a été téléchargé avec succès !")
        return redirect('dashboard')
    return render(request, 'watermark/upload.html')

# ✅ Protéger un document


# ✅ Lire un message caché


# ✅ Mes fichiers sécurisés
from django.shortcuts import render
from django.contrib.auth.decorators import login_required


@login_required


# ✅ Mon compte

# watermark/views.py

def profile_view(request):
    return render(request, 'watermark/profile.html')


# ✅ Paramètres
@login_required
def settings_view(request):
    return render(request, 'watermark/setting.html')

def home(request):
    return render(request, 'watermark/home.html')


def help_view(request):
    return render(request, 'watermark/help.html')

#==================================================================================================