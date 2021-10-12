from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class UserAddress(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    address_line1 = models.CharField(max_length=128)
    address_line2 = models.CharField(max_length=128)
    city = models.CharField(max_length=64)
    postal_code = models.CharField(max_length=16)
    country = models.CharField(max_length=64)
    phone = models.CharField(max_length=64)
    mobile = models.CharField(max_length=64)

    def __str__(self) -> str:
        return str(self.user)


class UserPayment(models.Model):
    # payment_type
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    payment = models.CharField(max_length=64)
    provider = models.CharField(max_length=64)
    account_no = models.IntegerField()
    expiry = models.DateField()

    def __str__(self) -> str:
        return f"{str(self.user)} - {str(self.account_no)}"