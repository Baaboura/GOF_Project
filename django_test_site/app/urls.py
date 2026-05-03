from django.urls import path
from . import views

urlpatterns = [
    path('',                views.home,         name='home'),
    path('login/',          views.login,        name='login'),
    path('search/',         views.search,       name='search'),
    path('admin-panel/',    views.admin_panel,  name='admin'),
    path('api/data/',       views.api_data,     name='api'),

    # Attack simulations
    path('ddos/',           views.ddos,         name='ddos'),
    path('sqli/',           views.sqli,         name='sqli'),
    path('xss/',            views.xss,          name='xss'),
    path('csrf/',           views.csrf_demo,    name='csrf'),
    path('csrf-target/',    views.csrf_target,  name='csrf_target'),
    path('malicious-url/',  views.malicious_url, name='malicious_url'),
]
