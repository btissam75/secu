from django.apps import AppConfig




class WatermarkConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'watermark'

    def ready(self):
        import watermark.signals





