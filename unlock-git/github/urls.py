from django.conf.urls import include, url
from django.contrib import admin

urlpatterns = [
    url(r'^', include('okta_oauth2.urls')),

]
