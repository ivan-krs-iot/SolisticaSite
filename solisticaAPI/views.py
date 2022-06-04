# Create your views here.

from rest_framework import generics
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .models import *
from .serializers import *
from django.shortcuts import get_object_or_404,get_list_or_404
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from .authentication import token_expire_handler, expires_in
from django.contrib.auth import authenticate
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK,
    HTTP_409_CONFLICT
)
from datetime import datetime, timezone,timedelta
from django.forms.models import model_to_dict
#from django.contrib.auth.models import User, Group

import stripe
import requests
import json

username=""
from django.db import connection
from tenant_schemas.utils import get_tenant_model
#from .models import Client
import logging
import logging.config
from django.contrib.auth.models import User,Group
import csv
from django.http import HttpResponse, JsonResponse
from django.core.mail import send_mail, BadHeaderError
from django.template.loader import render_to_string
from django.db.models.query_utils import Q
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.contrib.auth.tokens import default_token_generator
from django.utils.encoding import force_bytes

from random import randint
import time


server_main="https://fleet.krs-iot.com"


def is_auth(request):
	token_req=request.META["HTTP_AUTHORIZATION"]
	key=token_req[6:]
	try:
		token = Token.objects.get(key=key)
		return True
	except:
		return False



##Vista de Lista 
class VehiList(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request):
		queryset = vehiculo.objects.all()
		resL=[]
		for e in queryset:
			estado="ok"
			llantas=neumatico.objects.filter(trailer=e.epc)
			for ellant in llantas:
				ellantLastVer=historial.objects.filter(tipo__contains="verifica").filter(epc__exact=ellant.epc).order_by("-hora")
				if len(ellantLastVer)>1:
					if ellantLastVer[0].estado=="faltante":
						estado="faltante"
						break

			objLastVer=historial.objects.filter(tipo__contains="verifica").filter(epc__exact=e.epc)					
			if len(objLastVer)<1:
				estado="Sin registro"


			resI={"epc":e.epc,"placa":e.placa,"tipo":e.tipo,"layout":e.layout,"estado":estado}
			resL.append(resI)
		#permission_classes = (IsAuthenticated,)
		#objLastVer=historial.objects.filter(tipo__exact="verificación").filter(epc__exact=epc)
		#objLastVer=objLastVer[len(objLastVer)-1]

		return Response(resL)
'''
##Vista de Lista 
class VehiList(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request):
		queryset = vehiculo.objects.all()
		resL=[]
		for e in queryset:
			objLastVer=historial.objects.filter(tipo__exact="verificacion").filter(epc__exact=e.epc)
			if len(objLastVer)<1:
				resI={"epc":e.epc,"placa":e.placa,"tipo":e.tipo,"layout":e.layout,"estado":"Sin registro"}
			else:
				objLastVer=objLastVer[len(objLastVer)-1]
				resI={"epc":e.epc,"placa":e.placa,"tipo":e.tipo,"layout":e.layout,"estado":objLastVer.estado}
			resL.append(resI)
		#permission_classes = (IsAuthenticated,)
		#objLastVer=historial.objects.filter(tipo__exact="verificación").filter(epc__exact=epc)
		#objLastVer=objLastVer[len(objLastVer)-1]

		return Response(resL)
'''

##Vista de Lista (no requiere token)
class NeumList(generics.ListCreateAPIView):
	permission_classes = (IsAuthenticated,)
	queryset = neumatico.objects.all()
	serializer_class = NeumSerializer
	#permission_classes = (IsAuthenticated,)

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset,pk=self.kwargs['pk'],) 
		return obj

##Vista de Lista (no requiere token)
class HistList(generics.ListCreateAPIView):
	permission_classes = (IsAuthenticated,)
	queryset = historial.objects.all()
	serializer_class = HistSerializer
	#permission_classes = (IsAuthenticated,)

	def get_object(self):
		queryset = self.get_queryset()
		obj = get_object_or_404(queryset,pk=self.kwargs['pk'],) 
		return obj





class VehiDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		obj=get_object_or_404(vehiculo, epc__exact=epc)
		serializer = VehiSerializer(obj)
		return Response(serializer.data)

	def delete(self, request, epc):
		objL=get_list_or_404(vehiculo, epc__exact=epc)
		for obj in objL:
			obj.delete()
		return Response(status=status.HTTP_204_NO_CONTENT)

	def post(self, request, format=None):
		vehiObjs=vehiculo.objects.all()

		serializer = VehiSerializer(data = request.data)
		if serializer.is_valid():
			if request.data['epc'] in vehiculo.objects.values_list('epc', flat=True):
				return Response({'detail':'Error'}, status=status.HTTP_201_CREATED)
			else:
				if(request.data['epc'] in neumatico.objects.values_list('epc', flat=True)):
					return Response({'detail':'Error'}, status=status.HTTP_201_CREATED)
				else:
					serializer.save()
					return Response({'detail':'Exito'}, status=status.HTTP_201_CREATED)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

	def patch(self, request, epc):
		obj=get_object_or_404(vehiculo, epc__exact=epc)
		serializer = VehiSerializer(obj,data = request.data, partial=True)

		if serializer.is_valid():
			serializer.save()
			return Response(serializer.data, status= status.HTTP_201_CREATED)

		return Response(serializer.data,status=status.HTTP_400_BAD_REQUEST)

class NeumDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		obj=get_object_or_404(neumatico, epc__exact=epc)
		serializer = NeumSerializer(obj)
		return Response(serializer.data)

	def delete(self, request, epc):
		objL=get_list_or_404(neumatico, epc__exact=epc)
		for obj in objL:
			obj.delete()
		return Response(status=status.HTTP_204_NO_CONTENT)

	def post(self, request, format=None):
		serializer = NeumSerializer(data = request.data)
		if serializer.is_valid():
			if request.data['epc'] in neumatico.objects.values_list('epc', flat=True):
				return Response({'detail': 'Error'}, status=status.HTTP_201_CREATED)
			else:
				serializer.save()
				return Response({'detail': 'Exito'}, status= status.HTTP_201_CREATED)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

	def patch(self, request, epc):
		obj=get_object_or_404(neumatico, epc__exact=epc)
		serializer = NeumSerializer(obj,data = request.data, partial=True)

		if serializer.is_valid():
			serializer.save()

		return Response(serializer.data)


class EPCDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		objLV=vehiculo.objects.filter(epc=epc)
		objLN=neumatico.objects.filter(epc=epc)
		tipo="Desconocido"
		vehiculoEPC="Desconocido"
		neumaticosEPC=[]
		if objLV:
			for obj in objLV:
				tipo="vehiculo"
				vehiculoEPC=obj.epc
				neumL=neumatico.objects.filter(trailer=obj.epc)
				for neum in neumL:
					neumaticosEPC.append(neum.epc)
				break
		elif objLN:
			for obj in objLN:
				tipo="neumatico"
				vehiculoEPC=obj.trailer
				neumL=neumatico.objects.filter(trailer=obj.trailer)
				for neum in neumL:
					neumaticosEPC.append(neum.epc)
				break




		json_resp = {"tipo":tipo,"vehiculo":vehiculoEPC,"neumaticos":neumaticosEPC}
		return Response(json_resp)


class EPCDetailPlus(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		objLV=vehiculo.objects.filter(epc=epc)
		objLN=neumatico.objects.filter(epc=epc)
		tipo="Desconocido"
		vehiculoEPC="Desconocido"
		info="Desconocido"
		neumaticosEPC=[]
		if objLV:
			for obj in objLV:
				tipo="vehiculo"
				vehiculoEPC=obj.epc
				info=obj.placa
				neumL=neumatico.objects.filter(trailer=obj.epc)
				for neum in neumL:
					neumaticosEPC.append(neum.epc)
				break
		elif objLN:
			for obj in objLN:
				tipo="neumatico"
				vehiculoEPC=obj.trailer
				info=obj.pos
				neumL=neumatico.objects.filter(trailer=obj.trailer)
				for neum in neumL:
					neumaticosEPC.append(neum.epc)
				break




		json_resp = {"tipo":tipo,"info":info,"vehiculo":vehiculoEPC,"neumaticos":neumaticosEPC}
		return Response(json_resp)


class InfoDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		#objL=get_list_or_404(historial, epc__exact=epc)
		try:
			llantas=neumatico.objects.filter(trailer__exact=epc)
		except:
			logging.debug("Excepts")
			llantas=[]
		objAnt=historial.objects.filter(tipo__exact="registro").filter(epc__exact=epc)
		try:
			objAnt=objAnt[len(objAnt)-1]
			timediff = datetime.now(timezone.utc)-objAnt.hora
			antiguedad=timediff.days
		except:
			antiguedad="No se conoce el número de"
		objLastVer=historial.objects.filter(tipo__contains="verifica").filter(epc__exact=epc).order_by("-hora")
		objLastVer=objLastVer[0]



		estado="ok"
		List=[]
		for obj in llantas:	
			serializer=NeumSerializer(obj)
			llaAnt=historial.objects.filter(tipo__exact="registro").filter(epc__exact=serializer.data["epc"])
			try:
				llaAnt=llaAnt[len(llaAnt)-1]
				timediff = datetime.now(timezone.utc)-llaAnt.hora
				antiguedadNeum=timediff.days
			except:
				antiguedadNeum="No se conoce el número de"

			try:
				llaVer=historial.objects.filter(tipo__contains="verifica").filter(epc__exact=serializer.data["epc"]).order_by("-hora")
				#print(llaVer)
				llaVer=llaVer[0]
				if llaVer.estado=="faltante":
					estado="faltante"
				print("llaver")
				print(llaVer.hora)
				print(llaVer.estado)
				
			except:
				llaVer.estado="Desconocido"
			#serializerLlaAnt=HistSerializer(llaAnt)
			
			List.append({"epc":serializer.data["epc"],"pos":serializer.data["pos"],"antiguedad":antiguedadNeum,"estado":llaVer.estado})

		
		#logging.debug(timediff.days)
		#logging.debug(llaAnt.reverse()[0].hora)
		ubicacion="En custodia"
		if (objLastVer.movimiento.lower()=="salida"):
			ubicacion="En prestamo"


		serializer_data={"antiguedad":antiguedad,"estado":estado,"ubicacion":ubicacion,"desde":objLastVer.hora,"neumaticos":List}

		#serializer.data[0]={"etado":hola}	
		return Response(serializer_data)

class ValidDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		objL=get_list_or_404(validaciones, epc__exact=epc)
		serializer_data=[]
		for obj in objL:	
			serializer=ValidSerializer(obj)
			serializer_data.append(serializer.data)

		#serializer.data[0]={"etado":hola}	
		return Response(serializer_data)

	#def delete(self, request):
	#	queryset=historial.objects.all()
	#	queryset.delete()
	#	return Response(status=status.HTTP_204_NO_CONTENT)

	def delete(self, request, pk):
		obj=get_object_or_404(validaciones, pk=pk)
		obj.delete()
		return Response(status=status.HTTP_204_NO_CONTENT)


	def post(self, request, format=None):
		serializer = ValidSerializer(data = request.data)
		if serializer.is_valid():
			if request.data['epc'] in vehiculo.objects.values_list('epc', flat=True):
				return Response({'detail': 'Error'}, status=status.HTTP_201_CREATED)
			else:
				serializer.save()
				return Response({'detail': 'Exito'}, status= status.HTTP_201_CREATED)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

	def patch(self, request, pk):
		obj=get_object_or_404(validaciones, pk=pk)
		serializer = ValidSerializer(obj,data = request.data, partial=True)

		if serializer.is_valid():
			serializer.save()

		return Response(serializer.data)

class HistDetail(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request, epc):
		#new_token = Token.objects.create(user=request.user)
		objL=get_list_or_404(historial, epc__exact=epc)
		serializer_data=[]
		for obj in objL:	
			serializer=HistSerializer(obj)
			serializer_data.append(serializer.data)

		#serializer.data[0]={"etado":hola}	
		return Response(serializer_data)

	#def delete(self, request):
	#	queryset=historial.objects.all()
	#	queryset.delete()
	#	return Response(status=status.HTTP_204_NO_CONTENT)

	def delete(self, request, pk):
		obj=get_object_or_404(historial, pk=pk)
		obj.delete()
		return Response(status=status.HTTP_204_NO_CONTENT)


	def post(self, request, format=None):
		serializer = HistSerializer(data = request.data)
		if serializer.is_valid():
			serializer.save()
			return Response(serializer.data, status= status.HTTP_201_CREATED)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

	def patch(self, request, pk):
		obj=get_object_or_404(historial, pk=pk)
		serializer = HistSerializer(obj,data = request.data, partial=True)

		if serializer.is_valid():
			serializer.save()

		return Response(serializer.data)

##Clase con información de página perfil
class Perfil(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request):
		usrT=User.objects.get(username = request.user)
		schemaN=connection.schema_name
		connection.set_schema_to_public()
		tenantModel=tenantUser=get_tenant_model().objects.get(schema_name=schemaN)
		
		return Response({'nombreEmp':tenantModel.name,'rfc':tenantModel.rfc,'calle':tenantModel.calle,
			'ciudad':tenantModel.ciudad,'pais':tenantModel.pais,'cp':tenantModel.cp,'telefono':tenantModel.telefono,
			'nombre':usrT.first_name,'apellido':usrT.last_name,'email':usrT.email})
		

	def delete(self, request):
		pass
		return Response(status=status.HTTP_204_NO_CONTENT)


	def post(self, request, format=None):
		pass
		return Response(status=status.HTTP_204_NO_CONTENT)





#Vista de autenticación
class tokenView(APIView):
	def post(self,request, format=None):
		try:
			usernameVar=request.data['username']
			user = authenticate(
			username = usernameVar,
			password = request.data['password'] 
			)
			if not user:
				userEmail = User.objects.get(email=request.data['username'])
				usernameVar=userEmail.username
				user = authenticate(
				username = usernameVar,
				password = request.data['password'] 
				)
				if not user:
					return Response({'detail': 'Invalid Credentials or activate account'}, status=HTTP_404_NOT_FOUND)

			token, _ = Token.objects.get_or_create(user = user)
			is_expired, token = token_expire_handler(token)
			g_e=user.groups.all()
			grupoUser="Sin grupo"
			if g_e:
				grupoUser=g_e[0].name

			return Response({
			'user': usernameVar, 
			'expires_in': expires_in(token),
			'token': token.key,
			'grupo': grupoUser
			}, status=HTTP_200_OK)
		except Exception as e:
			print(e)
			return Response({'estado': 'Invalid Credentials or activate account'}, status=HTTP_404_NOT_FOUND)


class tokenCheckView(APIView):
	def post(self,request, format=None):
		try:
			token = Token.objects.get(key=request.data['token'])
			user = Token.objects.get(key=request.data['token']).user
		except:
			return Response({'valid': 'invalid'}, status=HTTP_200_OK)

		if not user:
			return Response({'valid': 'invalid'}, status=HTTP_200_OK)

		#token, _ = Token.objects.get_or_create(user = user)
		is_expired, token = token_expire_handler(token)
		username=user.username   
		return Response({
		'valid': is_expired,
		'user': user.username, 
		'expires_in': expires_in(token)
		}, status=HTTP_200_OK)














class user(APIView):
	permission_classes = (IsAuthenticated,)
	def get(self, request):
		objLI=User.objects.all()
		objL=list(objLI.values())
		for i,e in enumerate(objLI):
			objL[i]["password"]=""
			g_e=e.groups.all()
			if g_e:
				objL[i]["grupo"]=g_e[0].name
			else:
				objL[i]["grupo"]="Sin grupo"
			#objL.append(dict_e)
		
		return JsonResponse(objL,safe=False)
		

	def delete(self, request,username):
		us = User.objects.get(username = username)
		us.delete()
		
		return Response({"estado":"ok"})


	def post(self, request):
		try:
			user = User.objects.create_user(request.data["username"], request.data["email"], request.data["password"])
			userDict=model_to_dict(user)
			grupo = Group.objects.get(name=request.data["grupo"])
			print("GRUPO: ")
			print(grupo)
			user.groups.add(grupo)
			#user.save()
			#userDict=model_to_dict(user)
			
			userDict["password"]=""
			userDict["estado"]="ok"
			return JsonResponse(userDict,safe=False)
		except Exception as e:
			print(e)
			return JsonResponse({"estado":"error"},safe=False)


	


##---Descarga reporte----
class descarga(APIView):
	def get(self, request):
		logging.debug("Descarga ")
		response = HttpResponse(content_type='text/csv')
		response['Content-Disposition'] = 'attachment; filename="somefilename.csv"'

		writer = csv.writer(response)

		vehiculos=vehiculo.objects.all()

		#writer.writerow(["EPC", "Placa", "Tipo"])

		for obj in vehiculos:
			neumaticoL=neumatico.objects.filter(trailer__exact=obj.epc)
			histV=historial.objects.filter(epc__exact=obj.epc)
			#writer.writerow([obj.epc, obj.placa, obj.tipo])
			for hist in histV:
				writer.writerow([obj.epc,"vehículo",obj.placa, obj.tipo, obj.layout, hist.hora,hist.tipo, hist.movimiento, hist.estado])
			for neumObj in neumaticoL:
				histN=historial.objects.filter(epc__exact=neumObj.epc)
				for hN in histN:
					writer.writerow([neumObj.epc,"neumático",neumObj.idP, neumObj.pos, neumObj.trailer, hist.hora,hist.tipo, hist.movimiento, hist.estado])


		return response


##----Stripe----##

class payment_intent(APIView):
	stripe.api_key = 'sk_test_2EFSSu10xNDGiCY9PFG6PN4A00a5F0E5GV'
	def post(self, request):
		logging.debug("Payment intent")
		#logging.debug(request.data["currency"])
		user=str(request.user)
		logging.debug(user)
		obj=stripeCustomer.objects.filter(usuario=user)
		if obj:
			customer_id=obj[0].id_stripe
			logging.debug("Old Stripe customer "+user+" id: "+customer_id)
		else:
			customer = stripe.Customer.create()
			customer_id=customer['id']
			dataNewStripe={"usuario":user,"id_stripe":customer_id}
			logging.debug(dataNewStripe)
			serializer = StripeSerializer(data = dataNewStripe)
			if serializer.is_valid():
				serializer.save()
			logging.debug("New Stripe customer "+user+" id: "+customer_id)

		intent = stripe.PaymentIntent.create(
		  amount=int(request.data["amount"]),
		  currency=request.data["currency"],
		  description=request.data["items"],
		  customer=customer_id,
		  # Verify your integration in this guide by including this parameter
		  #metadata={'integration_check': 'accept_a_payment'},
		)

		return Response({'publishableKey': 'pk_test_bQE6oYNMPrTJGusQmmV8RBjK00jAg59WsZ', 'clientSecret':intent.client_secret}, status=HTTP_200_OK)

	def get(self, request):
		objL=stripeCustomer.objects.all()
		serializerL=[]
		for obj in objL:
			serializer = StripeSerializer(obj)
			serializerL.append(serializer.data)
		return Response(serializerL)


class payment_confirm(APIView):
	stripe.api_key = 'sk_test_2EFSSu10xNDGiCY9PFG6PN4A00a5F0E5GV'
	def post(self, request):
		logging.debug("Payment confirm")
		logging.debug(request.data)
		payment_id=request.data["payment_id"]
		logging.debug("Payment ID debbug")
		logging.debug(payment_id)
		payment=stripe.PaymentIntent.retrieve(payment_id)
		if payment.status=="succeeded":
			logging.debug("Payment Succedded")
			logging.debug(payment.description)
		else:
			logging.debug("Payment Fail")
			logging.debug(payment.description)

		return Response({'response': 'null'}, status=HTTP_200_OK)


class setup_intent(APIView):
	stripe.api_key = 'sk_test_2EFSSu10xNDGiCY9PFG6PN4A00a5F0E5GV'
	def post(self, request):
		logging.debug("Payment setup")
		#logging.debug(request.data["currency"])
		user=str(request.user)
		obj=stripeCustomer.objects.filter(usuario=user)
		if obj:
			customer_id=obj[0].id_stripe
			logging.debug("Old Stripe customer "+user+" id: "+customer_id)
		else:
			customer = stripe.Customer.create()
			customer_id=customer['id']
			dataNewStripe={"usuario":user,"id_stripe":customer_id}
			serializer = StripeSerializer(data = dataNewStripe)
			if serializer.is_valid():
				serializer.save()
			logging.debug("New Stripe customer "+user+" id: "+customer_id)

		intent = stripe.SetupIntent.create(
		  customer=customer_id
		)

		return Response({'publishableKey': 'pk_test_bQE6oYNMPrTJGusQmmV8RBjK00jAg59WsZ', 'clientSecret':intent.client_secret}, status=HTTP_200_OK)

###--- Recover password -###


class Reset_Pass(APIView):
    def post(self, request):
        data = request.data["email"]
        print("DATA --- "+str(len(data)))
        if len(data)<1:
        	return Response({'result': 'Null'}, status=HTTP_200_OK)
        associated_users = User.objects.filter(email=data)
        print(associated_users)
        
        if associated_users.exists():
            for user in associated_users:
                subject = "Restablecer contraseña"
                email_template_name = "reset_email.txt"
                c = {
                "email":user.email,
                'domain': server_main+'/recover-password',
                'site_name': 'Krs-Iot',
                "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                #"uid": user.pk,
                "user": user,
                'token': default_token_generator.make_token(user),
                }
                email = render_to_string(email_template_name, c)
                try:
                    send_mail(subject, email, 'soporte@krs-iot.com' , [user.email], fail_silently=False)
                    return Response({'result': 'Ok'}, status=HTTP_200_OK)
                except BadHeaderError:
                    return Response({'result': BadHeaderError}, status=HTTP_200_OK)
        else:
        	return Response({'result': 'NotFound'}, status=HTTP_200_OK)
        

class Recover_Pass(APIView):
    def post(self, request):
        new_password = request.data["new_password"]
        try:
        	uid=urlsafe_base64_decode(request.data["uid"])
        	token=request.data["token"]
        	associated_users = User.objects.filter(pk=uid)
        except:
        	return Response({'result': 'BadUID'}, status=HTTP_200_OK)
        #print(associated_users)
        
        if associated_users.exists():
            for user in associated_users:
            	if default_token_generator.check_token(user, token): #and user.is_active == 0
            		#print(user.is_active)
            		user.set_password(new_password)
            		#print(new_password)
            		user.save()
            		userName=user.username
            		connection.set_schema_to_public()
            		tenantUser=get_tenant_model().objects.get(schema_name=user.last_name)
            		connection.set_tenant(tenantUser)
            		user_schema = User.objects.filter(username=userName)
            		if user_schema.exists():
            			userS=user_schema[0]
            			userS.set_password(new_password)
            			userS.save()
            			return Response({'result': 'Ok'}, status=HTTP_200_OK)
            		else:
            			return Response({'result': 'NotFound(2)'}, status=HTTP_200_OK)

            	else:
            		return Response({'result': 'BadToken'}, status=HTTP_200_OK)
        else:
        	return Response({'result': 'NotFound'}, status=HTTP_200_OK)
        
        
