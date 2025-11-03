import os
import tinify
from .QuickDjango import qrender, use, QJR, exist_such_data
from .QuickDjango import login_, get_user, JsonResponse, logger
from .QuickDjango import logout_, redirect, valid_username_check
from .QuickDjango import force_login, read_in_chunks
from piggySQL.models import User, Bug, Message
from hashlib import sha1 as _sha1
from django.urls import path
from .NetDisk import Upload


def sha1(x):
    return _sha1(x.encode("utf8")).hexdigest()


AUTO_USERNAME = 0x01


class Users:

    @logger.catch
    def login(request):
        callback = request.GET.get("callback", "/")
        logger.info(
            f"{get_user(request)} requested login page with callback {callback}.")
        return qrender(request,
                       "login.html",
                       callback=False,
                       redirect=callback)

    @logger.catch
    def register(request):
        logger.info(f"{get_user(request)} requested register page.")
        return qrender(request, "register.html", callback=False)

    @logger.catch
    @use("GET")
    def register_action(request):
        Map = request.GET.get
        username = Map("username", None)
        password = Map("password", None)
        return Users.raw_register(request, username, password)

    @logger.catch
    def raw_register(request, name, pwd, isWX=0):
        logger.info(
            f"register action called with name: {name}, pwd: {pwd}, isWX: {isWX}")
        if name != AUTO_USERNAME:
            ok, name = valid_username_check(name)
            if not ok:
                return QJR(400, name)
            if User.objects.filter(username__exact=name).exists():
                return QJR(400, "User already exists")
        login_(request, name)
        u = User.objects.create(username=name, password=sha1(pwd), isWX=isWX)
        os.mkdir(f"./upload/{u.pk}")
        if name == AUTO_USERNAME:
            u.username = f"新用户 {u.pk}"
            u.save()
        return JsonResponse({"code": 200,
                             "data": str(u.pk),
                             "isSuperUser": int(u.isSuperUser),
                             "new_wx_user": isWX
                             })

    @logger.catch
    @use("GET")
    def login_action(request):
        Map = request.GET.get
        username = Map("username", None)
        pwd = Map("password", None)
        return Users.raw_login_action(request, username, pwd)

    @logger.catch
    def raw_login_action(request, u: str, pwd):
        logger.info(f"login action called with name: {u}, pwd: {pwd}")
        ok, u = valid_username_check(u)
        assert isinstance(u, str)
        if not ok:
            return QJR(400, u)
        if not exist_such_data(User, username=u):
            return QJR(404, "User not exists.")
        u = User.objects.get(username=u)
        if u.password == sha1(pwd):
            login_(request, u.username)
            res = {
                "code": 200,
                "data": str(u.pk),
                "isSuperUser": int(u.isSuperUser),
                "new_wx_user": u.username == u.isWX
            }
            logger.debug(res)
            return JsonResponse(res)
        else:
            return QJR(400, "Wrong password")

    @logger.catch
    @use("GET")
    def user_index_info(request):
        u = get_user(request)
        name = request.GET.get("UserFrom", u.pk)
        if isinstance(name, str) and not name.isdecimal():
            return QJR(400, "Only int can be passed to `UserFrom` param.")
        requested_user = User.objects.filter(pk=name)
        if not requested_user.exists():
            return QJR(404)
        requested_user = requested_user[0]
        logger.info(f"{u} request user_index_info of {requested_user}")
        if request.GET.get("_contentOnly", None) is not None:
            Json = {
                "username": requested_user.username,
                "head": requested_user.img,
                "pk": requested_user.pk,
                "coin": requested_user.coin,
                "isSuperUser": requested_user.isSuperUser
            }
            return QJR(200, Json)
        return qrender(request,
                       "UserIndex.html",
                       thisUser=requested_user.username,
                       img=requested_user.img,
                       callback="/IndexUser/")

    @logger.catch
    @use("GET")
    @force_login()
    def user_info_modify(request):
        user = get_user(request)
        name = request.GET.get("Username", None)
        if len(name) >= 16:
            return QJR(400)

        logger.info(f"{user} requested to modify his name to {name}")
        if exist_such_data(User, username=name):
            res = User.objects.get(username=name)
            if res.pk != user.pk:
                logger.warning(
                    f"{user}'s request is not done. Username has already exists: {res}.")
                return QJR(304, res.pk)

        if name:
            user.username = name
        else:
            return QJR(401)

        user.save()
        logout_(request)
        return QJR(200)

    @logger.catch
    def logout(request):
        logout_(request)
        return redirect("/")

    @logger.catch
    def exists(request):
        id = int(request.GET.get("pk"))
        if exist_such_data(User, id=id):
            return QJR(200, {
                "isSuperUser": User.objects.get(id=id).isSuperUser
            })
        else:
            return QJR(404)

    @logger.catch
    @use("POST")
    def change_img_action(request):
        u = get_user(request)
        tinify.key = "YNFTCtbXvr2Kcv7rwt891pGyK2QBrnPQ"
        source = tinify.from_buffer(request.FILES.get("upload_file").read())
        path = f"{u.pk}_head_icon.tmp"
        source.to_file(path)
        _res = Upload.upload(u, path, read_in_chunks(path), False)
        if not _res[0] == 200:
            return QJR(*res)
        else:
            res = _res[-1]
        u.img = res
        u.save()
        os.unlink(path)
        return QJR(200, res)

    @logger.catch
    def upload_bug(request):
        params = request.GET.get
        try:
            Bug.objects.create(content=params('content', ''),
                               logging=params('logging', ''))
        except Exception as err:
            print(err)
        return QJR(200)

    @logger.catch
    def getMessage(request):
        u = get_user(request)
        if u.Message_id < Message.objects.all().count():
            u.Message_id += 1
            u.save()
            return QJR(200, Message.objects.get(pk=u.Message_id).content)
        else:
            bugs = Bug.objects.filter(UserFrom=u.pk).exclude(reply="")
            if bugs.exists():
                replies = [f"您反馈的编号为 {i.pk} 的 Bug 回复为：{i.reply}" for i in bugs]
                return QJR(200, "\n".join(replies))
            else:
                return QJR(204)

    urls = [
        path('login/', login),
        path('logout/', logout),
        path('loginAction/', login_action),
        path('register/', register),
        path('registerAction/', register_action),
        path('UserModify/', user_info_modify),
        path('user_info/', user_index_info),
        path("exists/", exists),
        path("uploadBug/", upload_bug),
        path("change_img_action/", change_img_action),
        path("getMessage/", getMessage)
    ]
