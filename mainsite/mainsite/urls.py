"""mainsite URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
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
from .Phone_verify import invoke_send_message, verify_code, connect_user_to_phone

from . import views
from . import NetDisk

from .Users import Users

from django.conf import settings
from django.shortcuts import render, redirect
from django.conf.urls.static import static
from django.views.generic.base import RedirectView

favicon = r"https://cdn.luogu.com.cn/upload/image_hosting/xwx6rxi5.png"
urlpatterns = [
    path(r"favicon.ico", RedirectView.as_view(url=favicon)),
    path("whatsthis/", admin.site.urls),
    path('api/phone/send_code/', invoke_send_message,
         name='send_verification_code'),
    path('api/phone/verify/', verify_code, name='verify_phone_code'),
    path('api/user/connect/phone/', connect_user_to_phone,
         name='connect_user_to_phone')
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# paths
urlpatterns += Users.urls
# urlpatterns += views.urls
urlpatterns += NetDisk.urls
