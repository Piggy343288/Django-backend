from django.http import JsonResponse
from django.shortcuts import render, HttpResponse, redirect
import os
import time
import base64
import requests
from piggySQL.models import User
from loguru import logger


PERMITTED = 1
logger.add("./logs/log.log", rotation="10 MB")
HR = HttpResponse
SuccessLink = "/downloadAction?name=Li91cGxvYWQvNS9zdWNjZXNzLnR4dA=="
wx_key = {"appid": "wxedd5ba704cb5e248", "secret": "92b474dd55e39ddde3abf124ac32ce01"}
wx_url = "https://api.weixin.qq.com"
Admins = ["xiao"]
img_exts = ["jpg", "png", "jpeg", "gif"]
JsonResponses = {
    "100": "Continue",
    "101": "Switching Protocols",
    "200": "OK",
    "201": "Created",
    "202": "Accepted",
    "203": "Non-Authoritative Information",
    "204": "No Content",
    "205": "Reset Content",
    "206": "Partial Content",
    "300": "Multiple Choices",
    "301": "Moved Permanently",
    "302": "Found",
    "303": "See Other",
    "304": "Not Modified",
    "305": "Use Proxy",
    "306": "Unused",
    "307": "Temporary Redirect",
    "400": "Bad Request",
    "401": "Unauthorized",
    "402": "Payment Required",
    "403": "Forbidden",
    "404": "Not Found",
    "405": "Method Not Allowed",
    "406": "Not Acceptable",
    "407": "Proxy Authentication Required",
    "408": "Request Time-out",
    "409": "Conflict",
    "410": "Gone",
    "411": "Length Required",
    "412": "Precondition Failed",
    "413": "Request Entity Too Large",
    "414": "Request-URL Too Large",
    "415": "Unsupported Media Type",
    "416": "Requested range not satisfiable",
    "417": "Expectation Failed",
    "500": "Internal Server Error",
    "501": "Not Implemented",
    "502": "Bad Gateway",
    "503": "Service Unavailable",
    "504": "Gateway Time-out",
    "505": "HTTP Version not supported",
}

@logger.catch
def QJR(code, message=None) -> HttpResponse:
    try:
        code = str(code)
    except ValueError:
        return QJR(500, f"Unexpected {code} with type {str(type(code))}")

    statusCode = JsonResponses.get(code, "Unknown HTTP Status Code")
    message = statusCode if message is None else message
    return JsonResponse(
        {"code": code, "data": message}, json_dumps_params={"separators": (",", ":")}
    )

def use(method):
    def decoator(func):
        return lambda req: func(req) if req.method == method else QJR(405)
    return decoator

@logger.catch
def valid_username_check(u):
    if not u:
        return False, "Empty Username"
    if len(u) >= 60:
        return False, "Username too long"
    return True, u

@logger.catch
def b64encode(s: str | bytes):
    return base64.b64encode((s.encode() if isinstance(s, str) else s)).decode()

@logger.catch
def b64decode(s: str):
    return base64.b64decode(s).decode()

@logger.catch
def redirect_to_login(callback="/"):
    return redirect(f"/login/?callback={callback}")

@logger.catch
def is_login(req):
    return req.session.get("isLogin", None) == "true"

@logger.catch
def force_login(resp=redirect_to_login, judge=is_login):
    def decoator(func):
        def wrapper(req, *args, **kwargs):
            ret = judge(req)
            if ret == PERMITTED:
                return func(req, *args, **kwargs)
            else:
                return resp(ret)

        return wrapper

    return decoator

@logger.catch
def login_(request, username):
    request.session["isLogin"] = "true"
    request.session["username"] = username
    return request

@logger.catch
def logout_(request):
    request.session["isLogin"] = "false"
    request.session["username"] = "Guest"
    request.session.clear()
    request.session.flush()
    return request


Guest = User.objects.get(pk=16)

@logger.catch()
def get_user(request):
    user = request.session.get("username")
    logger.info(f"{user} {type(user)} called get_user.")
    if user is None:
        return Guest
    try:
        return User.objects.filter(username=user)[0]
    except Exception:
        logout_(request)
        return Guest

@logger.catch
def qrender(request, template, callback="/", admin=False, **kwargs):
    def wrapper(request, template, **kwargs):
        u = get_user(request)
        return render(
            request,
            template,
            context={"id": u.pk, "User": u.username, **kwargs},
        )
    if (admin and not callback):
        return QJR(400)
    re = None
    if callback:
        if admin:
            judge, resp = is_admin_request, lambda ret: redirect_to_login(callback) if ret == -1 else lambda: render(request, "403.html")
        else:
            judge, resp = is_login, lambda _: redirect_to_login(callback)
        re = force_login(resp, judge)(wrapper)
    else:
        re = wrapper
    return re(request, template, **kwargs)

@logger.catch
def file_is_image(name):
    return "." in name and name.split(".")[-1].lower() in img_exts

@logger.catch
def exist_such_data(Field, **kwargs):
    return Field.objects.filter(**kwargs).exists()

@logger.catch
def is_valid_user(userfrom):
    return userfrom and exist_such_data(User, id=userfrom)

@logger.catch
def is_admin(user):
    return user.isSuperUser

@logger.catch
def is_admin_request(req):
    return is_admin(get_user(req)) if is_login(req) else -1

@logger.catch
def have_permission(object, user):
    return is_admin(user) or object.UserFrom == user.pk

@logger.catch
def transfer(dic):
    res = {}
    for i, j in dict(dic).items():
        res[i] = j[-1]
    return res

@logger.catch
def get_size(dir):
    ans = 0
    for filename in os.listdir(dir):
        pathTmp = os.path.join(dir, filename)
        if os.path.isdir(pathTmp):
            ans += get_size(pathTmp)
        elif os.path.isfile(pathTmp):
            filesize = os.path.getsize(pathTmp)
            ans += filesize
    return ans



class access_token:
    def __init__(self):
        self.last_modify_time = -1
        self._access_token = ""
    
    @property
    def timestamp(self):
        return time.time()

    @property
    def access_token(self):
        if self.timestamp - self.last_modify_time >= 3600:
            url = f"{wx_url}/cgi-bin/token?grant_type=client_credential"
            self._access_token = requests.get(url, params=wx_key).json()["access_token"]
            self.last_modify_time = self.timestamp
        return self._access_token

token = access_token()

def read_in_chunks(file, chunk_size=1024):
    """Lazy function (generator) to read a file piece by piece.
    Default chunk size: 1k."""
    file_object = open(file, "rb")
    while True:
        data = file_object.read(chunk_size)
        if not data:
            file_object.close()
            break
        yield data
