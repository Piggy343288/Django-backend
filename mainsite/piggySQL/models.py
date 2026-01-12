from django.db import models
from django.utils.timezone import now
from datetime import datetime
import json
import os

defaultImg = "50269eff1afaf33db4929e2e596b0889"


# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=30, unique=True)
    password = models.CharField(max_length=40)
    img = models.CharField(max_length=200, default=defaultImg)
    isSuperUser = models.BooleanField(default=False)
    OccupiedSpace = models.IntegerField(default=0)
    Verified = models.BooleanField(default=False)
    uniapp_cid = models.CharField(max_length=200, default="")
    phone_number = models.CharField(
        max_length=11, unique=True, blank=True, null=True)


class File(models.Model):
    filePath = models.CharField(max_length=200)
    name = models.CharField(max_length=200, default="NULL")
    UserFrom = models.IntegerField(default=-1)
    isPrivate = models.BooleanField()
    hash_code = models.CharField(max_length=80, default="")
    ultimate_hash = models.CharField(max_length=80, default="")


def delete_user(user):
    os.rmdir(f"./upload/{user.pk}")
    for i in File.objects.filter(UserFrom=user.pk):
        i.delete()
    user.delete()

class PhoneVerify(models.Model):
    """手机号验证表"""
    phone_number = models.CharField(max_length=11)
    hashCode = models.CharField(max_length=100)
    verify_code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.phone_number} - {self.verify_code}"