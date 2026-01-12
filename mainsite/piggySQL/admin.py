from django.contrib import admin
from .models import User, File, PhoneVerify


class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'username', 'isSuperUser', 'Verified', 'phone_number']
    search_fields = ['username', 'phone_number']
    list_filter = ['isSuperUser', 'Verified']


class FileAdmin(admin.ModelAdmin):
    list_display = ['id', 'name', 'UserFrom', 'isPrivate', 'filePath']
    search_fields = ['name', 'filePath', 'hash_code']
    list_filter = ['isPrivate']


class PhoneVerifyAdmin(admin.ModelAdmin):
    list_display = ['id', 'phone_number', 'hashCode', 'verify_code', 'created_at']
    search_fields = ['phone_number', 'verify_code']
    list_filter = ['created_at']


def register(site=admin.site):
    site.register(User, UserAdmin)
    site.register(File, FileAdmin)
    site.register(PhoneVerify, PhoneVerifyAdmin)


register()
