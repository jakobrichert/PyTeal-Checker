from operator import index
from django.urls import path
from . import views

app_name = 'mainapp'

urlpatterns = [
    # Web interface
    path('', views.index, name="index"),
    path('index', views.index, name="index"),
    path('notvalid', views.notvalid, name='notvalid'),
    path('valid', views.valid, name='valid'),
    path('best', views.best, name='best'),
    path('about', views.about, name='about'),

    # REST API endpoints
    path('api/analyze', views.api_analyze, name='api_analyze'),
    path('api/health', views.api_health, name='api_health'),
    path('api/features', views.api_features, name='api_features'),
]