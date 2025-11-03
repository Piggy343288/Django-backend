from django.db import models
from django.utils.timezone import now
import json
import os

defaultImg = "50269eff1afaf33db4929e2e596b0889"


# Create your models here.
class User(models.Model):
    username = models.CharField(max_length=30)
    password = models.CharField(max_length=40)
    img = models.CharField(max_length=200, default=defaultImg)
    isWX = models.CharField(default="0", max_length=50)
    coin = models.IntegerField(default=3)
    boughtPapers = models.ManyToManyField(to="Paper", blank=True)
    isSuperUser = models.BooleanField(default=False)
    Message_id = models.IntegerField(default=0)
    OccupiedSpace = models.IntegerField(default=0)


class File(models.Model):
    filePath = models.CharField(max_length=200)
    name = models.CharField(max_length=200, default="NULL")
    UserFrom = models.IntegerField(default=-1)
    isPrivate = models.BooleanField()
    hash_code = models.CharField(max_length=80, default="")
    ultimate_hash = models.CharField(max_length=80, default="")

class Plan(models.Model):
    UserFrom = models.IntegerField(default=-1)
    Content = models.TextField(max_length=2000)
    undoPlans = models.TextField(max_length=2000, default="", blank=True)
    donePlans = models.TextField(max_length=2000, default="", blank=True)
    linkedFile = models.CharField(max_length=200, default="NULL")
    punishment = models.CharField(max_length=200, default="NULL")
    Date = models.DateTimeField(default=now)
    group = models.IntegerField(default=-1)


class Comment(models.Model):
    UserFrom = models.IntegerField(default=-1)
    Content = models.CharField(max_length=200)
    to_Article = models.IntegerField(default=-1)


class Article(models.Model):
    title = models.CharField(max_length=20)
    UserFrom = models.IntegerField(default=-1)
    isPrivate = models.BooleanField(default=False)
    tag = models.IntegerField(default=-1)
    content = models.CharField(max_length=32768, default="")


class Tag(models.Model):
    name = models.CharField(max_length=200, default="default")


class Paper(models.Model):
    name = models.CharField(max_length=2000, default="unknown")
    baiduPath = models.CharField(max_length=2000, default="")
    quarkPath = models.CharField(max_length=2000, default="")
    aliPath = models.CharField(max_length=2000, default="")
    type = models.IntegerField(default=0)
    subject = models.IntegerField(default=0)
    grade = models.IntegerField(default=0)
    comment = models.CharField(max_length=20000, default="")
    date = models.DateField(default="1970-01-01")
    bilibiliCode = models.CharField(default="", max_length=20)
    fullyname = models.CharField(max_length=2000, default="unknown")
    status = models.BooleanField(default=False)


class ChatMsg(models.Model):
    UserFrom = models.IntegerField()
    Content = models.CharField(max_length=2000)
    

class Like(models.Model):
    UserFrom = models.IntegerField(default=-1)
    to_Article = models.IntegerField(default=-1)


class Bug(models.Model):
    UserFrom = models.IntegerField(default=-1)
    content = models.CharField(max_length=2000)
    logging = models.CharField(max_length=20000)
    reply = models.CharField(max_length=2000, default="")


class Message(models.Model):
    content = models.CharField(max_length=2000)


def parse_user(Obj):
    """
    Args:
        Obj:[User|other objects which support 'UserFrom' Attr.]
    """
    if isinstance(Obj, User):
        _user = Obj
    else:
        _user = User.objects.get(id=Obj.UserFrom)
    return [_user.img, _user.username, _user.pk]


def Atc2Comments(Atc: Article):
    ans = []
    for i in Comment.objects.filter(to_Article=Atc.pk):
        ans.append([parse_user(i), i.Content])
    return json.dumps(ans)


def User2Json(u: User):
    return {"username": u.username, "head": u.img, "pk": u.pk}


def Subject2String(subject: int) -> str:
    ans = ""
    dic = "无 数学 语文 英语 物理 化学 生物 政治 历史 地理".split()
    for i in range(1, 11):
        if (subject & (1 << (i - 1))):
            ans += dic[i - 1] + " "
    return ans


def Grade2String(grade: int) -> str:
    ans = ""
    dic = "无 小学 初一 初二 初三 高一 高二 高三".split()
    for i in range(1, 9):
        if (grade & (1 << (i - 1))):
            ans += dic[i - 1] + " "
    return ans


def redo_paper(paper: Paper) -> None:
    subj = Subject2String(paper.subject)
    grad = Grade2String(paper.grade)
    paper.fullyname = paper.name + subj + grad + str(paper.pk)
    paper.save()


def delete_user(user):
    os.rmdir(f"./upload/{user.pk}")
    for i in File.objects.filter(UserFrom=user.pk):
        i.delete()
    for i in Plan.objects.filter(UserFrom=user.pk):
        i.delete()
    for i in Comment.objects.filter(UserFrom=user.pk):
        i.delete()
    for i in Article.objects.filter(UserFrom=user.pk):
        i.delete()
    for i in Group.objects.filter(admin=user.pk):
        i.delete()
    for i in ChatMsg.objects.filter(UserFrom=user.pk):
        i.delete()
    for i in Like.objects.filter(UserFrom=user.pk):
        i.delete()
    user.delete()
