from django.shortcuts import render, redirect
from transformers import data
from . import pytealmodel
from django.http import HttpResponse, HttpResponseRedirect
from .forms import NewUserForm


def index(request):
    if request.method == "POST":
        form = NewUserForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data['input']
            #implementation of the model 
            code = pytealmodel.main(data)
            if code == '1':
                return HttpResponseRedirect('/valid')
            if code == '0':
                return HttpResponseRedirect('/notvalid')
    
    else:
        form = NewUserForm()
    return render (request=request, template_name="mainapp/index.html", context={"form":form})
# Create your views here.


def notvalid(request):
    data = {}
    return render(request = request,template_name="mainapp/notvalid.html" )


def valid(request):
    data = {}
    return render(request = request,template_name="mainapp/valid.html" )

def best(request):
    data = {}
    return render(request = request,template_name="mainapp/best.html" )

def about(request):
    data = {}
    return render(request = request,template_name="mainapp/about.html" )