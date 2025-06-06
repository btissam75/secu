from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
from django.contrib.auth.decorators import login_required
from django.urls import path
from . import views

urlpatterns = [
    # page d’accueil / login
    path('', views.login_view, name='login'),
    path('register/', views.register, name='register'),
    path('logout/', views.userLogout, name='logout'),

    # Dashboard et pages associées
    path('home/', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),

    # Upload, profil, aide, paramètres
    path('upload/', views.upload_document, name='upload'),
    path('profile/', views.profile_view, name='profile'),
    path('help/', views.help_view, name='help'),
    path('settings/', views.settings_view, name='settings'),

    # Gestion des fichiers bruts
    path('delete/<int:doc_id>/', views.delete_file, name='delete_file'),
    path('classify/', views.classify_files, name='classify_files'),
    path('test-filter/', views.test_filter_view, name='test_filter'),

    # Protéger / déchiffrer
    path('protect/', views.protect, name='protect'),
    path('selected/', views.selected_files, name='selected_files'),
    path('decrypt/<int:securefile_id>/', views.decrypt, name='decrypt'),

    # Suppressions spécifiques
    path('delete-protected/<int:sf_id>/', views.delete_protected, name='delete_protected'),
    path('delete-decrypted/<int:doc_id>/', views.delete_decrypted, name='delete_decrypted'),

    # Liste des PDF déjà déchiffrés
    path('decrypted/', views.decrypted_list, name='decrypted_list'),
     path('encrypt/', login_required(views.EncryptView.as_view()), name='encrypt'),
    path('decrypt/', login_required(views.DecryptView.as_view()), name='decrypt'),
]
