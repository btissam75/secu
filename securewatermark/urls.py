# securewatermark/urls.py
from django.contrib import admin
from django.urls import path, include, reverse_lazy
from watermark import views
from django.contrib.auth import views as auth_views
from django.conf import settings
from django.conf.urls.static import static
from django.urls import path, include
urlpatterns = [
    # 1) Formulaire « Entrez votre e-mail pour réinitialiser »
    path(
        'password_reset/',
        auth_views.PasswordResetView.as_view(
            template_name='registration/password_reset_form.html',
            email_template_name='registration/password_reset_email.html',
            subject_template_name='registration/password_reset_subject.txt',
            success_url=reverse_lazy('password_reset_done'),
        ),
        name='password_reset'
    ),
path("", include("watermark.urls")),
    # 2) Page de confirmation « On a envoyé l’e-mail »
    path(
        'password_reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='registration/password_reset_done.html'
        ),
        name='password_reset_done'
    ),

    # 3) Lien cliqué depuis le mail : choisir un nouveau mot de passe
    path(
        'reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='registration/password_reset_confirm.html',
            success_url=reverse_lazy('password_reset_complete')
        ),
        name='password_reset_confirm'
    ),

    # 4) Page « Votre mot de passe a été modifié »
    path(
        'reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='registration/password_reset_complete.html'
        ),
        name='password_reset_complete'
    ),

  
    path('', views.home, name='home'),
    # path('accounts/', include('allauth.urls')),
    path('admin/', admin.site.urls),
    path('', include('watermark.urls')),  
    

    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_document, name='upload'),
    path('admin/', admin.site.urls),
    path('accounts/', include('allauth.urls')),
    path('', include('watermark.urls')),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)