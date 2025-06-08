# watermark/views.py
from django.contrib.auth.models import User



import os
import binascii
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required


from .models import DecryptedDocument

from .models import Document, SecureFile
from .forms import CreateNewUser
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils import embed_bytes_in_image, extract_bytes_from_image

# watermark/views.py

import os
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings

from django.urls import reverse
from django.contrib.auth import authenticate, login, logout


from .models import Profile, Document, SecureFile       # <-- Profile, Document, SecureFile importés depuis models.py
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils    import embed_bytes_in_image, extract_bytes_from_image

# Vos vues…

# ──────────────────────────── AUTHENTIFICATION ────────────────────────────

def login_view(request):
    if request.method == 'POST':
        identifiant = request.POST.get('username')
        password = request.POST.get('password')
        # Si l’utilisateur saisit un email, on le convertit en username
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

def selected_files(request):
    """
    Affiche deux sections :
      1. Les Document “sélectionnés” (is_selected=True)
      2. Les SecureFile (images stéganographiées contenant le PDF chiffré)
    """
    # 1) Tous les Document de l’utilisateur marqués is_selected=True
    selected_docs = Document.objects.filter(user=request.user, is_selected=True)

    # 2) Tous les SecureFile de l’utilisateur (images protégées)
    secure_files = SecureFile.objects.filter(user=request.user)

    return render(request, 'watermark/selected_files.html', {
        'documents': selected_docs,
        'secure_files': secure_files,
    })
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Profile

# watermark/views.py

from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.models import User
from .models import Profile




from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from .models import Profile



# watermark/views.py

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login
from django.contrib import messages
from .models import Profile

# watermark/views.py

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
# watermark/views.py

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login

from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages

# watermark/views.py

from django.shortcuts import render, redirect
# watermark/views.py

from django.shortcuts import render, redirect
from django.contrib import messages
# watermark/views.py

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.conf import settings
from django.http import HttpResponse, HttpResponseRedirect
from django.urls import reverse

from .models import Profile, Document, SecureFile, DecryptedDocument
from .forms  import RegisterForm
from .utils.crypto_utils  import encrypt_bytes, decrypt_bytes
from .utils.stego_utils   import embed_bytes_in_image, extract_bytes_from_image


                        # sinon, get_user_model() renverra django.contrib.auth.models.User

# watermark/views.py

from django.shortcuts           import render, redirect
from django.contrib.auth        import authenticate, login
from django.contrib             import messages
from django.contrib.auth.models import User
from .forms                     import RegisterForm
from .models                    import Profile

# def register(request):
   
#     # 2) Instanciation unique du formulaire
#     form = RegisterForm(request.POST or None)

#     # 3) Si le formulaire est valide, on traite
#     if form.is_valid():
#         username = form.cleaned_data['username']
#         email    = form.cleaned_data['email']
#         pwd      = form.cleaned_data['password1']

#         # 4) Vérification existence (username OU email)
#         if User.objects.filter(username__iexact=username).exists() \
#         or User.objects.filter(email__iexact=email).exists():
#             messages.info(request, 
#                 "Ce compte existe déjà – merci de vous connecter.")
#             return redirect('login')

#         # 5) Création de l'utilisateur
#         user = User.objects.create_user(
#             username=username,
#             email=email,
#             password=pwd
#         )
#         # 6) Création du profil (si vous n'utilisez pas de signal automatique)
#         Profile.objects.create(user=user)

#         # 7) Connexion automatique
#         user = authenticate(request, username=username, password=pwd)
#         if user:
#             login(request, user)

#         messages.success(request, "Votre compte a bien été créé.")
#         return redirect('login')

#     # 8) En GET ou en cas d’erreurs, on ré-affiche le formulaire
#     return render(request, 'watermark/register.html', {
#         'form': form
#     })

from django.shortcuts    import render, redirect
from django.contrib      import messages
from django.contrib.auth import get_user_model
from .forms              import RegisterForm
from django.db           import IntegrityError

User = get_user_model()

def register(request):
    

    form = RegisterForm(request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            username = form.cleaned_data['username']
            email    = form.cleaned_data['email']
            pwd1     = form.cleaned_data['password1']

            # 2) Si compte déjà existant, on redirige vers login avec info
            if User.objects.filter(username=username).exists() or User.objects.filter(email=email).exists():
                messages.info(request, "Un compte existe déjà pour cet utilisateur/email. Vous pouvez vous connecter.")
                return redirect('login')

            # 3) Sinon on crée le user
            try:
                user = User.objects.create_user(username=username, email=email, password=pwd1)
            except IntegrityError:
                # au cas (rare) où le profil aurait déjà été créé par un signal
                messages.info(request, "Votre compte semble déjà exister. Merci de vous connecter.")
                return redirect('login')

            messages.success(request, "Votre compte a bien été créé. Vous pouvez maintenant vous connecter.")
            return redirect('login')

    # GET ou form invalide : on ré-affiche le formulaire
    return render(request, 'watermark/register.html', {'form': form})



# ───────────────────────────── PAGES PUBLIQUES ─────────────────────────────

def home(request):
    return render(request, 'watermark/home.html')


def help_view(request):
    return render(request, 'watermark/help.html')

# … du code en haut de fichier …



# ─────────────────────────────── VUES PROTÉGER ───────────────────────────────

# watermark/views.py

import os
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from .models import SecureFile
from .utils.crypto_utils import encrypt_bytes
from .utils.stego_utils import embed_bytes_in_image

@login_required
def protect(request):
    """
    Vue permettant à l’utilisateur d’uploader un PDF et de le cacher chiffré dans une image PNG.
    """
    if request.method == 'POST':
        # "mode" pourra servir à d’autres types de protection (texte, image…), ici on vérifie “pdf”
        mode = request.POST.get('mode')

        # Clé AES (en prod, on définit settings.AES_KEY dans settings.py)
        key = getattr(settings, 'AES_KEY', b'\x02' * 32)

        if mode == 'pdf':
            uploaded_pdf = request.FILES.get('uploaded_pdf')
            cover_image   = request.FILES.get('cover_image')
            title         = request.POST.get('title') or (uploaded_pdf.name if uploaded_pdf else '')

            # Si l’utilisateur n’a pas sélectionné de PDF, on remonte une erreur
            if not uploaded_pdf:
                messages.error(request, "Veuillez sélectionner un fichier PDF à protéger.")
                return redirect('protect')

            # 1) Enregistrer temporairement le PDF sous media/temp/…
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            pdf_path = os.path.join(temp_dir, uploaded_pdf.name)
            with open(pdf_path, 'wb') as f:
                for chunk in uploaded_pdf.chunks():
                    f.write(chunk)

            # 2) Si l’utilisateur a fourni une image porteuse, on l’enregistre aussi en temp/
            if cover_image:
                cover_dir  = os.path.join(settings.MEDIA_ROOT, 'temp')
                os.makedirs(cover_dir, exist_ok=True)
                cover_path = os.path.join(cover_dir, cover_image.name)
                with open(cover_path, 'wb') as f2:
                    for chunk in cover_image.chunks():
                        f2.write(chunk)
            else:
                # Sinon, on prend une image par défaut : MEDIA_ROOT/default_carrier.png
                cover_path = os.path.join(settings.MEDIA_ROOT, 'default_carrier.png')
                if not os.path.exists(cover_path):
                    # Si elle est manquante, on supprime le PDF temporaire et on affiche un message
                    messages.error(request, "L’image porteuse par défaut (default_carrier.png) est introuvable.")
                    os.remove(pdf_path)
                    return redirect('protect')

            # 3) Lire le contenu du PDF et le chiffrer en mémoire
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
            encrypted_pdf = encrypt_bytes(pdf_data, key)

            # 4) Cacher le buffer chiffré dans l’image porteuse
            stego_dir = os.path.join(settings.MEDIA_ROOT, 'stego')
            os.makedirs(stego_dir, exist_ok=True)

            # Pour garantir un nom unique, on utilise user.id + timestamp
            import time, uuid
            timestamp = int(time.time())
            rand_suffix = uuid.uuid4().hex[:6]
            stego_filename = f"stego_{request.user.id}_{timestamp}_{rand_suffix}.png"
            stego_path = os.path.join(stego_dir, stego_filename)

            # Appel à la fonction stéganographie
            embed_bytes_in_image(cover_path, encrypted_pdf, stego_path)

            # 5) Enregistrer en base : on stocke le chemin relatif par rapport à MEDIA_ROOT
            rel_path = os.path.relpath(stego_path, settings.MEDIA_ROOT)
            SecureFile.objects.create(
                user=request.user,
                name=title or uploaded_pdf.name,
                file=rel_path,         # ex : 'stego/stego_3_1623071234_ab12cd.png'
                file_type='image'
            )

            # 6) Nettoyage des fichiers temporaires
            os.remove(pdf_path)
            if cover_image and os.path.exists(cover_path):
                os.remove(cover_path)

            messages.success(request, "Le PDF a été chiffré et caché dans une image PNG.")
            return redirect('selected_files')

    # Si GET, on affiche simplement le formulaire Protect
    return render(request, 'watermark/protect.html')


@login_required
def classify_files(request):
    """
    Traite le formulaire où l’utilisateur coche/décoche ses documents.
    """
    if request.method == 'POST':
        chosen_ids = request.POST.getlist('selected_files')
        # Désélectionner d’abord tout
        Document.objects.filter(user=request.user).update(is_selected=False)
        # Sélectionner uniquement ceux cochés
        Document.objects.filter(user=request.user, id__in=chosen_ids).update(is_selected=True)

    return redirect('selected_files')


# watermark/views.py
from django.shortcuts import render, redirect, get_object_or_404, HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.conf import settings
import os, time, uuid

from .models import Document, SecureFile
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils   import embed_bytes_in_image, extract_bytes_from_image
@login_required
def delete_decrypted(request, doc_id):
    doc = get_object_or_404(DecryptedDocument, id=doc_id, user=request.user)
    # Supprimer le fichier physique (optionnel)
    filepath = os.path.join(settings.MEDIA_ROOT, doc.file.name)
    if os.path.exists(filepath):
        os.remove(filepath)
    # Supprimer la ligne en base
    doc.delete()
    return redirect('decrypted_list')

@login_required
def selected_files(request):
    """
    Affiche :
     - D’une part, la liste des Documents “bruts” que l’utilisateur a cochés (is_selected=True).
     - D’autre part, la liste des images stéganographiées (SecureFile) déjà générées.
    """
    raw_docs         = Document.objects.filter(user=request.user, is_selected=True)
    protected_images = SecureFile.objects.filter(user=request.user)

    return render(request,
                  'watermark/selected_files.html',
                  {
                      'raw_docs': raw_docs,
                      'protected_images': protected_images,
                  })



@login_required
def delete_file(request, doc_id):
    """
    Supprime un Document (fichier physique + entrée DB) pour l’utilisateur courant.
    """
    document = get_object_or_404(Document, id=doc_id, user=request.user)
    document.uploaded_file.delete()
    document.delete()
    return HttpResponseRedirect(reverse('dashboard'))


# ───────────────────────────── PAGES UTILISATEUR ─────────────────────────────
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Document, SecureFile

@login_required
def dashboard(request):
    """
    Affiche le tableau de bord avec :
    - tous les Documents de l'utilisateur
    - tous les SecureFile (fichiers protégés), triés du plus récent au plus ancien
    - quelques compteurs (en attente, en échec, dernier document…)
    """

    # 1) On récupère tous les documents de l’utilisateur, triés par date d’upload (champ `uploaded_at`)
    documents = Document.objects.filter(user=request.user).order_by('-uploaded_at')

    # 2) Compteurs « en attente » / « en échec » (adapter selon l’existence d’un champ status)
    try:
        pending_count = documents.filter(status='pending').count()
    except:
        pending_count = 0

    try:
        error_count = documents.filter(status='error').count()
    except:
        error_count = 0

    # 3) Dernier document (le plus récent)
    last_doc = documents.first()  # None si l’utilisateur n’a pas encore de document

    # 4) On récupère tous les SecureFile (fichiers protégés), 
    #    triés du plus récent au plus ancien, en ordonnant par ID décroissant
    securefiles = SecureFile.objects.filter(user=request.user).order_by('-id')

    # 5) On envoie tout ça dans le contexte du template
    return render(
        request, 
        'watermark/dashboard.html', 
        {
            'documents': documents,
            'pending_count': pending_count,
            'error_count': error_count,
            'last_doc': last_doc,
            'securefiles': securefiles,
        }
    )



from django.shortcuts import render

def test_filter_view(request):
    # Cette vue ne fait qu'afficher un template de test.
    return render(request, 'watermark/test_filter.html')
# watermark/views.py
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required


from django.contrib import messages
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

from .models import Document

@login_required
def upload_document(request):
    
    if request.method == 'POST' and request.FILES.get('document'):
        fichier = request.FILES['document']
        # Création du Document en base
        Document.objects.create(
            user=request.user,
            title=fichier.name,
            uploaded_file=fichier
        )
        messages.success(request, f"Le fichier « {fichier.name} » a été téléchargé avec succès !")
        return redirect('dashboard')

    return render(request, 'watermark/upload.html')


from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from .models import SecureFile

@login_required
def delete_protected(request, sf_id):
    sf = get_object_or_404(SecureFile, id=sf_id, user=request.user)
    sf.file.delete()
    sf.delete()
    return redirect('selected_files')

@login_required
def profile_view(request):
    return render(request, 'watermark/profile.html')


# watermark/views.py

@login_required
def settings_view(request):
    user = request.user
    profile, _ = Profile.objects.get_or_create(user=user)

    if request.method == "POST":
        # 1) Informations personnelles
        new_username = request.POST.get('username', "").strip()
        new_email = request.POST.get('email', "").strip()
        if new_username and new_username != user.username:
            user.username = new_username
        if new_email and new_email != user.email:
            user.email = new_email

        # Photo de profil
        if 'profile_pic' in request.FILES:
            profile.profile_pic = request.FILES['profile_pic']

        # 2) Changer mot de passe
        new_password = request.POST.get('password', "").strip()
        if new_password:
            user.set_password(new_password)
            messages.success(request, "Le mot de passe a été mis à jour.")

        # 3) Activer/désactiver 2FA
        twofa_checked = bool(request.POST.get('enable_2fa'))
        profile.two_factor_enabled = twofa_checked

        # 4) Préférence “mode sombre”
        dark_mode_selected = bool(request.POST.get('dark_mode'))
        user.save()
        profile.save()

        # Préparer la réponse (avec le cookie “dark_mode”)
        response = HttpResponseRedirect(reverse('settings'))
        if dark_mode_selected:
            response.set_cookie('dark_mode', '1', max_age=60*60*24*30, path='/')
        else:
            response.set_cookie('dark_mode', '0', max_age=60*60*24*30, path='/')
        return response

    # GET ou en cas d’erreur, on renvoie simplement la page avec le contexte
    return render(request, 'watermark/settings.html', {
        'documents': Document.objects.filter(user=request.user),
    })


# ──────────────────────────── CHIFFRER / DÉCHIFFRER ────────────────────────────
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
import os
from .models import SecureFile
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils import embed_bytes_in_image, extract_bytes_from_image

@login_required
def protect(request):
    """
    Si mode='pdf', on chiffre le PDF puis on cache les octets chiffrés dans une image.
    """
    if request.method == 'POST':
        mode = 'pdf'  # ici on force “pdf” pour l’exemple
        key = settings.AES_KEY

        # 1) récupérer le PDF et l’image porteuse
        uploaded_pdf = request.FILES.get('uploaded_pdf')
        cover_image = request.FILES.get('cover_image')

        if uploaded_pdf:
            # --- Enregistrer temporairement le PDF dans MEDIA_ROOT/temp/ ---
            temp_dir = os.path.join(settings.MEDIA_ROOT, 'temp')
            os.makedirs(temp_dir, exist_ok=True)
            pdf_path = os.path.join(temp_dir, uploaded_pdf.name)
            with open(pdf_path, 'wb') as f:
                for chunk in uploaded_pdf.chunks():
                    f.write(chunk)

            # --- Si l’utilisateur a fourni une image porteuse, on l’enregistre aussi ---
            if cover_image:
                cover_path = os.path.join(temp_dir, cover_image.name)
                with open(cover_path, 'wb') as f2:
                    for c in cover_image.chunks():
                        f2.write(c)
            else:
                # Sinon une image par défaut (préalablement placée, ex. “default_carrier.png”)
                cover_path = os.path.join(settings.MEDIA_ROOT, 'default_carrier.png')

            # 2) lecture du PDF en bytes
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()

            # 3) chiffrement symétrique (AES) -> encrypt_bytes(pdf_data, key) renvoie b'\xIV...ciphertext...'
            encrypted_pdf = encrypt_bytes(pdf_data, key)

            # 4) on compose un nom unique pour le fichier stego
            import time
            timestamp = int(time.time())
            stego_filename = f"stego_{request.user.id}_{timestamp}.png"
            stego_path = os.path.join(settings.MEDIA_ROOT, stego_filename)

            # 5) cacher les octets chiffrés dans l’image porteuse
            embed_bytes_in_image(cover_path, encrypted_pdf, stego_path)

            # 6) enregistrer en base (SecureFile) pour pouvoir le lister plus tard
            rel_path = os.path.relpath(stego_path, settings.MEDIA_ROOT)
            SecureFile.objects.create(
                user=request.user,
                name=uploaded_pdf.name,
                file=rel_path,       # ex : “stego_3_1623060000.png”
                file_type='image'
            )

            # 7) nettoyer les fichiers temporaires 
            os.remove(pdf_path)
            if cover_image:
                os.remove(cover_path)

            return redirect('selected_files')

    # Si GET, on affiche simplement le formulaire
    return render(request, 'watermark/protect.html')

@login_required
def protect_pdf_into_image(request):
    """
    Alternative : fonction de test pour chiffrer un PDF déjà stocké dans MEDIA_ROOT/uploads/mon_doc.pdf
    """
    pdf_path = os.path.join(settings.MEDIA_ROOT, "uploads", "mon_doc.pdf")
    if not os.path.exists(pdf_path):
        return HttpResponse("Le fichier mon_doc.pdf n’existe pas dans MEDIA_ROOT/uploads/.")

    with open(pdf_path, "rb") as f:
        pdf_data = f.read()

    key = getattr(settings, 'AES_KEY', b'\x02' * 32)
    iv_and_ct = encrypt_bytes(pdf_data, key)

    input_img  = os.path.join(settings.BASE_DIR, "watermark", "static", "img", "base_image.png")
    output_dir = os.path.join(settings.MEDIA_ROOT, "stego")
    os.makedirs(output_dir, exist_ok=True)
    stego_path = os.path.join(output_dir, f"stego_{request.user.id}.png")

    embed_bytes_in_image(input_img, iv_and_ct, stego_path)

    return HttpResponse(f"Document chiffré → {stego_path}")


@login_required
def extract_pdf_from_image(request):
    """
    Déchiffre l’image stego et redonne un PDF téléchargeable.
    """
    stego_path = os.path.join(settings.MEDIA_ROOT, "stego", "stego_{0}.png".format(request.user.id))
    if not os.path.exists(stego_path):
        return HttpResponse("L’image stéganographiée n’a pas été trouvée.")

    extracted = extract_bytes_from_image(stego_path)
    key = getattr(settings, 'AES_KEY', b'\x02' * 32)

    try:
        pdf_decrypted = decrypt_bytes(extracted, key)
    except Exception as e:
        return HttpResponse(f"Erreur de déchiffrement : {e}")

    out_dir = os.path.join(settings.MEDIA_ROOT, "recovered")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, f"recovered_{request.user.id}.pdf")
    with open(out_path, "wb") as out_f:
        out_f.write(pdf_decrypted)

    response = HttpResponse(pdf_decrypted, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="recovered_{request.user.id}.pdf"'
    return response



# watermark/views.py (à la fin du fichier, par exemple)

from django.shortcuts            import get_object_or_404, HttpResponse
from .models                     import SecureFile
from .utils.crypto_utils         import decrypt_bytes
from .utils.stego_utils          import extract_bytes_from_image

import os
from django.http import HttpResponse, HttpResponseRedirect
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.contrib.auth.decorators import login_required
# from .models import SecureFile, DecryptedDocument
from .utils.crypto_utils import decrypt_bytes
from .utils.stego_utils import extract_bytes_from_image

@login_required
def decrypt(request, securefile_id):
    """
    Extrait l’octet-array caché dans l’image stéganographiée, déchiffre le PDF,
    renvoie soit un téléchargement du PDF, soit l’affiche en HTML (si c’était un texte).
    Enregistre également le PDF déchiffré dans MEDIA_ROOT/decrypted_pdfs/ et en base.
    """
    sf = get_object_or_404(SecureFile, id=securefile_id, user=request.user)
    key = getattr(settings, 'AES_KEY', b'\x02' * 32)

    # 1) lire l’image stéganographiée et en extraire le buffer
    stego_path = os.path.join(settings.MEDIA_ROOT, sf.file.name)
    encrypted = extract_bytes_from_image(stego_path)

    # 2) déchiffrer (AES)
    try:
        decrypted_bytes = decrypt_bytes(encrypted, key)
    except Exception as e:
        return HttpResponse(f"Erreur de déchiffrement : {e}")

    # 3) Choisir un nom de fichier de sortie
    #    Par exemple : recovered_<origine>.pdf
    original_name = sf.name
    if original_name.lower().endswith('.pdf'):
        out_filename = f"recovered_{original_name}"
    else:
        # on force .pdf si besoin
        out_filename = f"recovered_{sf.id}.pdf"

    # 4) Écrire physiquement sous MEDIA_ROOT/decrypted_pdfs/
    decrypted_dir = os.path.join(settings.MEDIA_ROOT, 'decrypted_pdfs')
    os.makedirs(decrypted_dir, exist_ok=True)
    out_path = os.path.join(decrypted_dir, out_filename)

    with open(out_path, 'wb') as out_f:
        out_f.write(decrypted_bytes)

    # 5) Enregistrer en base le DecryptedDocument
    rel_path = os.path.relpath(out_path, settings.MEDIA_ROOT)
    DecryptedDocument.objects.create(
        user=request.user,
        name=original_name,
        file=rel_path
    )

    # 6) Renvoie la réponse HTTP pour téléchargement du PDF
    response = HttpResponse(decrypted_bytes, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{out_filename}"'
    return response
# from .models import DecryptedDocument

@login_required
def decrypted_list(request):
    """
    Affiche la liste (tableau ou cartes) de tous les DecryptedDocument
    que l’utilisateur a déjà extraits.
    """
    # Récupère tous les PDF déchiffrés pour l’utilisateur
    decrypted_docs = DecryptedDocument.objects.filter(user=request.user).order_by('-decrypted_at')
    return render(request, 'watermark/decrypted_list.html', {
        'decrypted_docs': decrypted_docs
    })
from django.shortcuts import get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.conf import settings
import os
# from .models import DecryptedDocument  # <— remplacez par votre modèle

@login_required
def delete_decrypted(request, doc_id):
    """
    Supprime l’objet DecryptedDocument identifié par doc_id, puis redirige vers decrypted_list.
    """
    # 1) Récupère l’enregistrement ou renvoie 404 si l’utilisateur n’y a pas accès
    decrypted = get_object_or_404(DecryptedDocument, id=doc_id, user=request.user)

    # 2) Si vous stockez physiquement le PDF dans MEDIA_ROOT, supprimez-le aussi
    if decrypted.file:
        chemin_fichier = os.path.join(settings.MEDIA_ROOT, decrypted.file.name)
        if os.path.exists(chemin_fichier):
            os.remove(chemin_fichier)

    # 3) Supprime l’enregistrement en base
    decrypted.delete()

    # 4) Retourne à la liste des PDF déchiffrés
    return redirect('decrypted_list')
@login_required
def decrypted_list(request):
    """
    Affiche tous les PDF déchiffrés pour l’utilisateur courant.
    """
    # Récupère les objets pour l’utilisateur connecté
    decrypted_docs = DecryptedDocument.objects.filter(user=request.user).order_by('-decrypted_at')

    return render(request, 'watermark/decrypted_list.html', {
        'decrypted_docs': decrypted_docs
    })
#=====================================================
# watermark/models.py  (ou créez un nouveau fichier models_messaging.py si vous voulez isoler)
from django.db import models
from django.conf import settings
from django.utils import timezone



class Message(models.Model):
    sender    = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    recipient = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_messages')
    subject   = models.CharField(max_length=200, blank=True)
    body      = models.TextField()
    sent_at   = models.DateTimeField(default=timezone.now)
    read      = models.BooleanField(default=False)

    class Meta:
        ordering = ['-sent_at']  # Les messages les plus récents en premier

    def __str__(self):
        return f"De {self.sender} → {self.recipient} ({self.sent_at:%d/%m/%Y %H:%M})"
#________________________________________________________________wijdane______________....

from django.shortcuts import render, redirect
from django.http import HttpResponse, FileResponse
from django.views.generic import TemplateView, FormView
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
from PIL import Image
import io
import os
from .utils.crypto_utils import encrypt_bytes, decrypt_bytes
from .utils.stego_utils    import embed_bytes_in_image, extract_bytes_from_image

from django import forms

class ImageUploadForm(forms.Form):
    image = forms.ImageField(
        label="Image",
        widget=forms.FileInput(attrs={'class': 'form-control', 'accept': 'image/*'})
    )
    
class EncryptForm(ImageUploadForm):
    message = forms.CharField(
        label="Message",
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 4, 'placeholder': 'Entrez votre message secret...'})
    )
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Mot de passe pour chiffrer'})
    )

class DecryptForm(ImageUploadForm):
    password = forms.CharField(
        label="Mot de passe",
        widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Mot de passe pour déchiffrer'})
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
            # Open and process the image
            img = Image.open(image_file)
            img_format = img.format if img.format else 'PNG'
            
            # Ensure image is in RGB for LSB
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Encrypt the message
            encrypted_data = encrypt_message(message, password)
            if not encrypted_data:
                form.add_error(None, "Échec du chiffrement.")
                return self.form_invalid(form)
                
            # Hide encrypted data in the image
            stego_image = hide_data_in_image(img, encrypted_data)
            if not stego_image:
                form.add_error(None, "Échec de la dissimulation des données dans l'image. Les données sont peut-être trop volumineuses pour cette image.")
                return self.form_invalid(form)
                
            # Prepare image for download
            output_buffer = io.BytesIO()
            stego_image.save(output_buffer, format='PNG')
            output_buffer.seek(0)
            
            # Create response with the image
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
            # Open and process the image
            img = Image.open(image_file)
            
            # Ensure image is in RGB for LSB
            if img.mode != 'RGB':
                img = img.convert('RGB')
                
            # Reveal data from the image
            revealed_data = reveal_data_from_image(img)
            if not revealed_data:
                form.add_error(None, "Échec de la révélation des données de l'image. Aucun message caché trouvé ou délimiteur manquant.")
                return self.form_invalid(form)
                
            # Decrypt the revealed data
            decrypted_message = decrypt_message(revealed_data, password)
            if decrypted_message is None:
                form.add_error(None, "Échec du déchiffrement. Mot de passe incorrect ou données corrompues.")
                return self.form_invalid(form)
                
            # Return the same page with the decrypted message
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






