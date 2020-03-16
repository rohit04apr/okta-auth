from django.urls import path, include
from django.conf.urls import url

from . import views

urlpatterns = [
    url(r'^$', views.home_controller, name='home_controller'),
    url(r'^login', views.login_controller, name='login_controller'),
    url(r'^oauth2/callback', views.callback_controller, name='callback_controller'),

    path('unlock/', views.unlock, name="unlock"),
]
