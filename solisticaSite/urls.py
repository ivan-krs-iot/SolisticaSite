"""solisticaSite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf.urls import url
from django.views.static import serve
from solisticaAPI.views import *
from rest_framework.authtoken import views
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('token/', tokenView.as_view() ),
    path('token', tokenView.as_view() ),
    path('tokenCheck/', tokenCheckView.as_view() ),
    path('API/vehiculoList', VehiList.as_view()),
    path('API/neumaticoList', NeumList.as_view()),
    path('API/vehiculo', VehiDetail.as_view()),
    path('API/vehiculo/<str:epc>', VehiDetail.as_view()),
    path('API/neumatico', NeumDetail.as_view()), 
    path('API/neumatico/<str:epc>', NeumDetail.as_view()),
    path('API/historialList', HistList.as_view()), 
    path('API/historial', HistDetail.as_view()), 
    path('API/historial/<int:pk>', HistDetail.as_view()),
    path('API/historial/<str:epc>', HistDetail.as_view()),
    path('API/info/<str:epc>', InfoDetail.as_view()),      
    path('API/usuario', user.as_view()),
    path('API/usuario/<str:username>', user.as_view()),
    path('API/paymentIntent', payment_intent.as_view()),
    path('API/paymentConfirm', payment_confirm.as_view()),
    path('API/setupIntent', setup_intent.as_view()),
    path('API/descarga', descarga.as_view()),
    path('API/epc/<str:epc>', EPCDetail.as_view()),
    path('API/epc_plus/<str:epc>', EPCDetailPlus.as_view()),
    url(r'^static/(?P<path>.*)$', serve,{'document_root': settings.STATIC_ROOT}),
    path('API/reset-password', Reset_Pass.as_view()), 
    path('API/recover-password', Recover_Pass.as_view()), 
    path('API/perfil', Perfil.as_view()),
    path('API/validaciones', ValidDetail.as_view())
]