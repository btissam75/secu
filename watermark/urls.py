from django.urls import path
from . import views
from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('', views.login_view, name='login'),
    path('home/', views.home, name='home'),
    path('register/', views.register, name='register'),
     path('login/', views.login_view, name='login'),
    path('logout/', views.userLogout, name='logout'),
    path('dashboard/', views.dashboard, name='dashboard'),
    path('upload/', views.upload_document, name='upload'),
    path('profile/', views.profile_view, name='profile'),
    path('help/', views.help_view, name='help'),
    path('settings/', views.settings_view, name='settings'),
path('delete/<int:doc_id>/', views.delete_file, name='delete_file'),

 path('protect/', views.protect, name='protect'),
 
path('protect/', views.protect, name='protect'),
path('classify/', views.classify_files, name='classify_files'),
path('test-filter/', views.test_filter_view, name='test_filter'),
path('selected/',                   views.selected_files, name='selected_files'),
    path('decrypt/<int:securefile_id>/', views.decrypt,       name='decrypt'),

path(
        'delete-protected/<int:sf_id>/',
        views.delete_protected,
        name='delete_protected'
    ),    
    path(
        'delete-protected/<int:sf_id>/',
        views.delete_protected,
        name='delete_protected'
    ),
    path('decrypted/', views.decrypted_list, name='decrypted_list'),

]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

#===============================================================================================