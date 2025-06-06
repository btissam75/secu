# watermark/views.py
from django.contrib.auth.models import User
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect, FileResponse
from django.urls import reverse, reverse_lazy
from django.conf import settings
from django.contrib import messages
from django.views.generic import TemplateView, FormView
from django.utils import timezone
from PIL import Image
import os
import binascii
import io
import time
import uuid

from .models import Profile, Document, SecureFile, DecryptedDocument
from .forms import RegisterForm
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils import embed_bytes_in_image, extract_bytes_from_image

User = get_user_model()

# ──────────────────────────── AUTHENTIFICATION ────────────────────────────

def login_view(request):
    if request.method == 'POST':
        identifiant = request.POST.get('username')
        password = request.POST.get('password')
        
        # Si l'utilisateur saisit un email, on le convertit en username
        if '@' in identifiant:
            try:
                user_obj = User.objects.get(email=identifiant)
                username = user_obj.username
            except User.DoesNotExist:
                messages.error(request, "Adresse e-mail introuvable.")
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


def userLogout(request):
    logout(request)
    return redirect('home')


def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            email = form.cleaned_data['email']
            pwd1 = form.cleaned_data['password1']

            # Vérifier qu'aucun utilisateur n'existe déjà
            if User.objects.filter(username=username).exists():
                messages.error(request, "Ce nom d'utilisateur est déjà pris.")
            elif User.objects.filter(email=email).exists():
                messages.error(request, "Cette adresse email est déjà utilisée.")
            else:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=pwd1
                )
                Profile.objects.create(user=user)

                user = authenticate(request, username=username, password=pwd1)
                if user is not None:
                    login(request, user)

                messages.success(request, "Votre compte a bien été créé.")
                return redirect('login')
    else:
        form = RegisterForm()

    return render(request, 'watermark/register.html', {'form': form})



# ───────────────────────────── PAGES PUBLIQUES ─────────────────────────────

def home(request):
    return render(request, 'watermark/home.html')


def help_view(request):
    return render(request, 'watermark/help.html')


# ───────────────────────────── PAGES UTILISATEUR ─────────────────────────────

@login_required
def dashboard(request):
    """
    Affiche le tableau de bord avec tous les fichiers de l'utilisateur
    """
    documents = Document.objects.filter(user=request.user).order_by('-uploaded_at')
    
    # Compteurs
    try:
        pending_count = documents.filter(status='pending').count()
    except:
        pending_count = 0

    try:
        error_count = documents.filter(status='error').count()
    except:
        error_count = 0

    last_doc = documents.first()
    securefiles = SecureFile.objects.filter(user=request.user).order_by('-id')

    return render(request, 'watermark/dashboard.html', {
        'documents': documents,
        'pending_count': pending_count,
        'error_count': error_count,
        'last_doc': last_doc,
        'securefiles': securefiles,
    })


@login_required
def upload_document(request):
    if request.method == 'POST' and request.FILES.get('document'):
        fichier = request.FILES['document']
        Document.objects.create(
            user=request.user,
            title=fichier.name,
            uploaded_file=fichier
        )
        messages.success(request, f"Le fichier « {fichier.name} » a été téléchargé avec succès !")
        return redirect('dashboard')

    return render(request, 'watermark/upload.html')


@login_required
def profile_view(request):
    return render(request, 'watermark/profile.html')


@login_required
def settings_view(request):
    user = request.user
    profile, _ = Profile.objects.get_or_create(user=user)

    if request.method == "POST":
        # Informations personnelles
        new_username = request.POST.get('username', "").strip()
        new_email = request.POST.get('email', "").strip()
        
        if new_username and new_username != user.username:
            user.username = new_username
        if new_email and new_email != user.email:
            user.email = new_email

        # Photo de profil
        if 'profile_pic' in request.FILES:
            profile.profile_pic = request.FILES['profile_pic']

        # Changer mot de passe
        new_password = request.POST.get('password', "").strip()
        if new_password:
            user.set_password(new_password)
            messages.success(request, "Le mot de passe a été mis à jour.")

        # 2FA
        twofa_checked = bool(request.POST.get('enable_2fa'))
        profile.two_factor_enabled = twofa_checked

        # Mode sombre
        dark_mode_selected = bool(request.POST.get('dark_mode'))
        
        user.save()
        profile.save()

        response = HttpResponseRedirect(reverse('settings'))
        if dark_mode_selected:
            response.set_cookie('dark_mode', '1', max_age=60*60*24*30, path='/')
        else:
            response.set_cookie('dark_mode', '0', max_age=60*60*24*30, path='/')
        return response

    return render(request, 'watermark/settings.html', {
        'documents': Document.objects.filter(user=request.user),
    })


# ─────────────────────────────── PROTECTION DE FICHIERS ───────────────────────────────

@login_required
def protect(request):
    """
    Vue permettant de protéger un PDF en le chiffrant et le cachant dans une image
    """
    if request.method == 'POST':
        mode = request.POST.get('mode', 'pdf')
        key = getattr(settings, 'AES_KEY', b'\x02' * 32)

        if mode == 'pdf':
            uploaded_pdf = request.FILES.get('uploaded_pdf')
            cover_image = request.FILES.get('cover_image')
            title = request.POST.get('title') or (uploaded_pdf.name if uploaded_pdf else '')

            if not uploaded_pdf:
                messages.error(request, "Veuillez sélectionner un fichier PDF à protéger.")
                return redirect('protect')

            # Enregistrer temporairement le PDF
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            pdf_path = os.path.join(temp_dir, uploaded_pdf.name)
            
            with open(pdf_path, 'wb') as f:
                for chunk in uploaded_pdf.chunks():
                    f.write(chunk)

            # Gérer l'image porteuse
            if cover_image:
                cover_path = os.path.join(temp_dir, cover_image.name)
                with open(cover_path, 'wb') as f2:
                    for chunk in cover_image.chunks():
                        f2.write(chunk)
            else:
                cover_path = os.path.join(settings.MEDIA_ROOT, 'default_carrier.png')
                if not os.path.exists(cover_path):
                    messages.error(request, "L'image porteuse par défaut est introuvable.")
                    os.remove(pdf_path)
                    return redirect('protect')

            # Chiffrer le PDF
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            encrypted_pdf = encrypt_bytes(pdf_data, key)

            # Créer l'image stéganographiée
            stego_dir = os.path.join(settings.MEDIA_ROOT, 'stego')
            os.makedirs(stego_dir, exist_ok=True)

            timestamp = int(time.time())
            rand_suffix = uuid.uuid4().hex[:6]
            stego_filename = f"stego_{request.user.id}_{timestamp}_{rand_suffix}.png"
            stego_path = os.path.join(stego_dir, stego_filename)

            embed_bytes_in_image(cover_path, encrypted_pdf, stego_path)

            # Enregistrer en base
            rel_path = os.path.relpath(stego_path, settings.MEDIA_ROOT)
            SecureFile.objects.create(
                user=request.user,
                name=title or uploaded_pdf.name,
                file=rel_path,
                file_type='image'
            )

            # Nettoyage
            os.remove(pdf_path)
            if cover_image and os.path.exists(cover_path):
                os.remove(cover_path)

            messages.success(request, "Le PDF a été chiffré et caché dans une image PNG.")
            return redirect('selected_files')

    return render(request, 'watermark/protect.html')


@login_required
def selected_files(request):
    """
    Affiche les fichiers sélectionnés et protégés
    """
    raw_docs = Document.objects.filter(user=request.user, is_selected=True)
    protected_images = SecureFile.objects.filter(user=request.user)

    return render(request, 'watermark/selected_files.html', {
        'raw_docs': raw_docs,
        'protected_images': protected_images,
        'documents': raw_docs,  # Pour compatibilité
        'secure_files': protected_images,  # Pour compatibilité
    })


@login_required
def classify_files(request):
    """
    Traite la sélection de fichiers
    """
    if request.method == 'POST':
        chosen_ids = request.POST.getlist('selected_files')
        Document.objects.filter(user=request.user).update(is_selected=False)
        Document.objects.filter(user=request.user, id__in=chosen_ids).update(is_selected=True)

    return redirect('selected_files')


# ─────────────────────────────── DÉCHIFFREMENT ───────────────────────────────

@login_required
def decrypt(request, securefile_id):
    """
    Déchiffre un fichier protégé
    """
    sf = get_object_or_404(SecureFile, id=securefile_id, user=request.user)
    key = getattr(settings, 'AES_KEY', b'\x02' * 32)

    # Extraire et déchiffrer
    stego_path = os.path.join(settings.MEDIA_ROOT, sf.file.name)
    encrypted = extract_bytes_from_image(stego_path)

    try:
        decrypted_bytes = decrypt_bytes(encrypted, key)
    except Exception as e:
        return HttpResponse(f"Erreur de déchiffrement : {e}")

    # Préparer le nom de fichier
    original_name = sf.name
    if original_name.lower().endswith('.pdf'):
        out_filename = f"recovered_{original_name}"
    else:
        out_filename = f"recovered_{sf.id}.pdf"

    # Sauvegarder physiquement
    decrypted_dir = os.path.join(settings.MEDIA_ROOT, 'decrypted_pdfs')
    os.makedirs(decrypted_dir, exist_ok=True)
    out_path = os.path.join(decrypted_dir, out_filename)

    with open(out_path, 'wb') as out_f:
        out_f.write(decrypted_bytes)

    # Enregistrer en base
    rel_path = os.path.relpath(out_path, settings.MEDIA_ROOT)
    DecryptedDocument.objects.create(
        user=request.user,
        name=original_name,
        file=rel_path
    )

    # Retourner le PDF
    response = HttpResponse(decrypted_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{out_filename}"'
    return response


@login_required
def decrypted_list(request):
    """
    Liste des fichiers déchiffrés
    """
    decrypted_docs = DecryptedDocument.objects.filter(user=request.user).order_by('-decrypted_at')
    return render(request, 'watermark/decrypted_list.html', {
        'decrypted_docs': decrypted_docs
    })


# ─────────────────────────────── SUPPRESSION ───────────────────────────────

@login_required
def delete_file(request, doc_id):
    """
    Supprime un document
    """
    document = get_object_or_404(Document, id=doc_id, user=request.user)
    document.uploaded_file.delete()
    document.delete()
    return HttpResponseRedirect(reverse('dashboard'))


@login_required
def delete_protected(request, sf_id):
    """
    Supprime un fichier protégé
    """
    sf = get_object_or_404(SecureFile, id=sf_id, user=request.user)
    sf.file.delete()
    sf.delete()
    return redirect('selected_files')


@login_required
def delete_decrypted(request, doc_id):
    """
    Supprime un fichier déchiffré
    """
    decrypted = get_object_or_404(DecryptedDocument, id=doc_id, user=request.user)
    
    if decrypted.file:
        chemin_fichier = os.path.join(settings.MEDIA_ROOT, decrypted.file.name)
        if os.path.exists(chemin_fichier):
            os.remove(chemin_fichier)
    
    decrypted.delete()
    return redirect('decrypted_list')


# ─────────────────────────────── VUES DE TEST ───────────────────────────────

def test_filter_view(request):
    """
    Vue de test pour les filtres
    """
    return render(request, 'watermark/test_filter.html')


# ─────────────────────────────── FONCTIONS UTILITAIRES STÉGANOGRAPHIE ───────────────────────────────

def encrypt_message(message, password):
    """
    Chiffre un message avec un mot de passe
    """
    try:
        key = password.encode('utf-8').ljust(32, b'\0')[:32]  # Clé de 32 bytes
        return encrypt_bytes(message.encode('utf-8'), key)
    except Exception:
        return None


def decrypt_message(encrypted_data, password):
    """
    Déchiffre des données avec un mot de passe
    """
    try:
        key = password.encode('utf-8').ljust(32, b'\0')[:32]  # Clé de 32 bytes
        decrypted_bytes = decrypt_bytes(encrypted_data, key)
        return decrypted_bytes.decode('utf-8')
    except Exception:
        return None


def hide_data_in_image(image, data):
    """
    Cache des données dans une image using LSB
    """
    try:
        # Convertir les données en binaire
        binary_data = ''.join(format(byte, '08b') for byte in data)
        binary_data += '1111111111111110'  # Délimiteur de fin
        
        pixels = list(image.getdata())
        
        if len(binary_data) > len(pixels) * 3:
            return None  # Pas assez de place
            
        data_index = 0
        new_pixels = []
        
        for pixel in pixels:
            if data_index < len(binary_data):
                r, g, b = pixel
                
                # Modifier le LSB de chaque canal
                if data_index < len(binary_data):
                    r = (r & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                if data_index < len(binary_data):
                    g = (g & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                if data_index < len(binary_data):
                    b = (b & 0xFE) | int(binary_data[data_index])
                    data_index += 1
                    
                new_pixels.append((r, g, b))
            else:
                new_pixels.append(pixel)
                
        new_image = Image.new('RGB', image.size)
        new_image.putdata(new_pixels)
        return new_image
        
    except Exception:
        return None


def reveal_data_from_image(image):
    """
    Révèle les données cachées dans une image
    """
    try:
        pixels = list(image.getdata())
        binary_data = ""
        
        for pixel in pixels:
            r, g, b = pixel
            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)
            
        # Chercher le délimiteur
        delimiter = '1111111111111110'
        end_index = binary_data.find(delimiter)
        
        if end_index == -1:
            return None
            
        # Extraire les données utiles
        data_binary = binary_data[:end_index]
        
        # Convertir en bytes
        data_bytes = bytearray()
        for i in range(0, len(data_binary), 8):
            if i + 8 <= len(data_binary):
                byte = data_binary[i:i+8]
                data_bytes.append(int(byte, 2))
                
        return bytes(data_bytes)
        
    except Exception:
        return None


# ─────────────────────────────── VUES POUR STÉGANOGRAPHIE AVANCÉE ───────────────────────────────

from django import forms

class ImageUploadForm(forms.Form):
    image = forms.ImageField(
        label="Image",
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'})
    )

class EncryptForm(ImageUploadForm):
    message = forms.CharField(
        label="Message",
        widget=forms.Textarea(attrs={
            'class': 'form-control', 
            'rows': 4, 
            'placeholder': 'Entrez votre message secret...'
        })
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Mot de passe pour chiffrer'
        })
    )

class DecryptForm(ImageUploadForm):
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={
            'class': 'form-control', 
            'placeholder': 'Mot de passe pour déchiffrer'
        })
    )


class EncryptView(LoginRequiredMixin, FormView):
    template_name = 'core/encrypt.html'
    form_class = EncryptForm
    success_url = reverse_lazy('core:encrypt')
    
    def form_valid(self, form):
        image_file = form.cleaned_data['image']
        message = form.cleaned_data['message']
        password = form.cleaned_data['password']
        
        try:
            img = Image.open(image_file)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            encrypted_data = encrypt_message(message, password)
            if not encrypted_data:
                form.add_error(None, "Échec du chiffrement.")
                return self.form_invalid(form)
                
            stego_image = hide_data_in_image(img, encrypted_data)
            if not stego_image:
                form.add_error(None, "Données trop volumineuses pour cette image.")
                return self.form_invalid(form)
                
            output_buffer = io.BytesIO()
            stego_image.save(output_buffer, format='PNG')
            output_buffer.seek(0)
            
            response = HttpResponse(output_buffer.getvalue(), content_type='image/png')
            response['Content-Disposition'] = 'attachment; filename="stego_image.png"'
            return response
            
        except Exception as e:
            form.add_error(None, f"Une erreur s'est produite: {str(e)}")
            return self.form_invalid(form)
            
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context


class DecryptView(LoginRequiredMixin, FormView):
    template_name = 'core/decrypt.html'
    form_class = DecryptForm
    success_url = reverse_lazy('core:decrypt')
    
    def form_valid(self, form):
        image_file = form.cleaned_data['image']
        password = form.cleaned_data['password']
        
        try:
            img = Image.open(image_file)
            
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            revealed_data = reveal_data_from_image(img)
            if not revealed_data:
                form.add_error(None, "Aucun message caché trouvé.")
                return self.form_invalid(form)
                
            decrypted_message = decrypt_message(revealed_data, password)
            if decrypted_message is None:
                form.add_error(None, "Mot de passe incorrect.")
                return self.form_invalid(form)
                
            context = self.get_context_data(form=form)
            context['decrypted_message'] = decrypted_message
            return self.render_to_response(context)
            
        except Exception as e:
            form.add_error(None, f"Une erreur s'est produite: {str(e)}")
            return self.form_invalid(form)
            
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['user'] = self.request.user
        return context