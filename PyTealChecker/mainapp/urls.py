from operator import index
from django.urls import path
from . import views

app_name = 'mainapp'

urlpatterns = [
    path('', views.index, name="index"),path('notvalid',views.notvalid, name='notvalid'),
    path('valid', views.valid, name='valid'), path('best', views.best, name='best'),
    path('about',views.about,name='about'),path('index', views.index, name="index"),

]