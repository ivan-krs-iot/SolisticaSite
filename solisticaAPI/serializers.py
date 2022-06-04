from .models import *
from rest_framework import serializers




class VehiSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = vehiculo
		fields = ('id','epc','placa','tipo','layout')

class NeumSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = neumatico
		fields = ('id','epc','idP','pos','trailer')

class ValidSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = validaciones
		fields = ('id','epc','fecha','antena','coordenadas','equipo')

class HistSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = historial
		fields = ('id','epc','hora','tipo','movimiento','estado','lugar','usuario','presion','antena')

class SigninSerializer(serializers.Serializer):
	username = serializers.CharField(required = True)
	password = serializers.CharField(required = True)

class TokenSerializer(serializers.Serializer):
	token = serializers.CharField(required = True)

class StripeSerializer(serializers.HyperlinkedModelSerializer):
	class Meta:
		model = stripeCustomer
		fields = ('id','usuario','id_stripe')

class PerfilUsrSerializer(serializers.Serializer):
	nombre = serializers.CharField(required = True,max_length=15)
	apellido = serializers.CharField(required = True,max_length=30)
	email = serializers.EmailField(required = True,max_length=30)




	
