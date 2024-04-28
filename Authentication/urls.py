from django.contrib import admin
from django.urls import path,include

from account import views

urlpatterns = [
    path("",views.home,name='home'),
    path("admin/", admin.site.urls),
    path("account/api/",include('account.urls')),
]
