from django.urls import path
from . import views

urlpatterns = [
    path('',        views.home,    name='home'),
    path('login/',  views.login,   name='login'),
    path('search/', views.search,  name='search'),
    path('admin-panel/', views.admin_panel, name='admin'),
    path('api/data/', views.api_data, name='api'),
]
