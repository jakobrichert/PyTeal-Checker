from attr import attr, attrs
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


# Create your forms here.

class NewUserForm(forms.Form):
	input = forms.CharField(max_length=1000000, widget=forms.Textarea(attrs={'cols': 70, 'rows': 5}))
