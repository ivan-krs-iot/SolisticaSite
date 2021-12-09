from rest_framework.authtoken.models import Token
from datetime import timedelta
from django.utils import timezone
from django.conf import settings

##Se maneja el tiempo de vida de cada token

def expires_in(token):
	time_elapsed = timezone.now() - token.created
	left_time = timedelta(minutes = settings.TOKEN_EXPIRED_AFTER_MINUTES) - time_elapsed
	return left_time

# Checa si el token ya expiró
def is_token_expired(token):
	return expires_in(token) < timedelta(seconds = 0)

# si el token expira se establece uno nuevo
def token_expire_handler(token):
	is_expired = is_token_expired(token)
	if is_expired:
		token.delete()
		token = Token.objects.create(user = token.user)
	return is_expired, token