from django.contrib import admin
from user.models import UserAddress, UserPayment

admin.site.register(UserAddress)
admin.site.register(UserPayment)