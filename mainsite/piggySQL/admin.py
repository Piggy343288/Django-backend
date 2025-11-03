from django.contrib import admin
from .models import Tag, User, File, Plan, Article
from .models import Comment, Paper, ChatMsg
from .models import Bug, Message

# Register your models here.


def register(models):
    for i in models:
        admin.site.register(i)

class UserAdmin(admin.ModelAdmin):
 
    # 定义列表中要显示哪些字段
    list_display = ['id', "username"]
    search_fields = ['username']

admin.site.register(User, UserAdmin)

register([
    Tag, File, Plan,
    Article, Comment, Paper, ChatMsg,
    Bug, Message
])
