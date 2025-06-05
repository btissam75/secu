from django import template

register = template.Library()

@register.filter
def endswith(value, arg):
    """
    Renvoie True si la chaîne `value` se termine par `arg`.
    Usage dans un template :
        {% load custom_filters %}
        {% if some_string|endswith:".pdf" %}
          … afficher un lien PDF …
        {% endif %}
    """
    try:
        return str(value).endswith(arg)
    except (ValueError, TypeError):
        return False
