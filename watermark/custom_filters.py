from django import template

register = template.Library()

@register.filter
def upper(value):
    return value.upper()

from django import template

register = template.Library()

@register.filter
def endswith(value, arg):
    """
    Renvoie True si la chaîne `value` se termine par `arg`.
    Exemple d’utilisation : {{ some_string|endswith:".pdf" }}
    """
    return str(value).endswith(arg)
