from django.db import models


class ProductCategory(models.Model):
    name = models.CharField(max_length=128)
    description = models.TextField()

    def __str__(self) -> str:
        return self.name


class ProductInventory(models.Model):
    quantity = models.IntegerField()
    created_at = models.DateTimeField()
    modified_at = models.DateTimeField()
    deleted_at = models.DateTimeField()

    def __str__(self) -> str:
        return f"{self.id} {self.quantity}"


class Discount(models.Model):
    name = models.CharField(max_length=256)
    description = models.TextField()
    discount_percent = models.FloatField()
    active = models.BooleanField()
    created_at = models.DateTimeField()
    modified_at = models.DateTimeField()
    deleted_at = models.DateTimeField()


class Product(models.Model):
    name = models.CharField(max_length=128)
    description = models.TextField()
    SKU = models.CharField(max_length=56)
    category = models.ForeignKey('ProductCategory', on_delete=models.CASCADE)
    inventory = models.OneToOneField(
        'ProductInventory',
        on_delete=models.CASCADE,
        primary_key=True,
    )
    price = models.FloatField()
    discount = models.ForeignKey('Discount', on_delete=models.SET_NULL)
    created_at = models.DateTimeField()
    modified_at = models.DateTimeField()
    deleted_at = models.DateTimeField()