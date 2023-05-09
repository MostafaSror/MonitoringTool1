from django import forms
from .models import Server, Group


class ServerForm(forms.ModelForm):
    class Meta:
        model = Server
        fields = [
            'IP',
            'hostname',
            'name',
        ]

class GroupForm(forms.ModelForm):
    class Meta:
        model = Group
        fields = [
            'groupName'
        ]

class ServerPureForm(forms.Form):
    IP= forms.CharField()
    hostname= forms.CharField()
    name= forms.CharField()