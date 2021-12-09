from django.conf import settings
from django.db.models.signals import post_save
from django.dispatch import receiver
#from rest_framework.authtoken.models import Token

from django.db import models
from django.core.validators import MinValueValidator
from django.contrib.postgres.fields import *


from datetime import datetime, timezone,timedelta


class vehiculo(models.Model):
	epc = models.CharField(max_length=50)
	placa = models.CharField(max_length=10)
	tipo = models.CharField(max_length=15)
	layout = models.CharField(max_length=25)

class neumatico(models.Model):
	epc = models.CharField(max_length=50)
	idP = models.CharField(max_length=20)
	pos = models.CharField(max_length=10)
	trailer = models.CharField(max_length=50)
	

class historial(models.Model):
	epc = models.CharField(max_length=50)
	hora =  models.DateTimeField(auto_now_add=True)
	tipo = models.CharField(max_length=20)
	movimiento = models.CharField(max_length=20)
	estado = models.CharField(max_length=15)
	lugar = models.CharField(max_length=50,default="Desconocido")
	usuario = models.CharField(max_length=30,default="Desconocido")
	presion = models.FloatField(default=0.0)

class stripeCustomer(models.Model):
	usuario = models.CharField(max_length=50)
	id_stripe =  models.CharField(max_length=50)

# Create your models here.
