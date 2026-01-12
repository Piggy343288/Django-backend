#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from piggySQL.models import User
import jwt
import time
import os
import hashlib
import json
import base64
import django
import requests

from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings
from loguru import logger

# JWT配置
JWT_ALGORITHM = 'HS256'
JWT_EXPIRY_YEARS = 100  # 100年有效期

# 现有的导入保持不变


PERMITTED = 1
logger.add("./logs/log.log", rotation="10 MB")
HR = HttpResponse
SuccessLink = "/downloadAction?name=Li91cGxvYWQvNS9zdWNjZXNzLnR4dA=="
wx_key = {"appid": "wxedd5ba704cb5e248",
          "secret": "92b474dd55e39ddde3abf124ac32ce01"}
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
        return QJR(500, f"Unexpected {code} with type {str(type(code))} invoked with message {message}")

    statusCode = JsonResponses.get(code, "Unknown HTTP Status Code")
    message = statusCode if message is None else message
    return JsonResponse(
        {"code": code, "data": message}, json_dumps_params={"separators": (",", ":")}
    )


def use(method):
    def decoator(func):
        def wrapper(req, *args, **kwargs):
            if req.method == method:
                return func(req, *args, **kwargs)
            else:
                return QJR(405, "不支持的请求方法")
        return wrapper
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
    # 优先检查JWT认证
    if is_login_jwt(req):
        return True

    # 如果JWT失败，回退到session检查
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


# 获取或创建Guest用户
# try:
#     Guest = User.objects.get(username='Guest')
# except User.DoesNotExist:
#     # 如果Guest用户不存在，创建一个
#     Guest = User(username='Guest', password='guest_password',
#                  isSuperUser=False)
#     Guest.save()


@logger.catch()
def get_user(request):
    """
    获取当前用户信息（优先从JWT认证，其次从Session，最后返回Guest）

    Args:
        request: Django HTTP请求对象

    Returns:
        User对象
    """
    # 优先尝试从JWT获取用户信息
    user_from_jwt = get_user_from_jwt(request)
    if user_from_jwt:
        logger.info(
            f"User {user_from_jwt.username} authenticated via JWT (get_user)")
        return user_from_jwt

    # 如果JWT获取失败，回退到Session
    # 检查request是否有session属性且是真正的session对象
    if hasattr(request, 'session') and request.session:
        user = request.session.get("username")
        logger.info(
            f"{user} {type(user)} called get_user (fallback to session).")
        if user is None:
            return Guest
        try:
            return User.objects.filter(username=user)[0]
        except Exception:
            # 只有当session对象有flush方法时才调用logout
            if hasattr(request.session, 'flush') and callable(getattr(request.session, 'flush')):
                logout_(request)
            else:
                logger.warning(
                    "Session object doesn't have flush method, skipping logout")
            return Guest
    else:
        # 如果没有session，直接返回Guest
        logger.info(
            "None (no session) called get_user (no JWT or session available)")
        return Guest


@logger.catch
def qrender(request, template, callback="/", admin=False, **kwargs):
    def wrapper(request, template, **kwargs):
        # 优先使用JWT获取用户信息
        u = get_user_jwt(request)
        return render(
            request,
            template,
            context={"id": u.pk, "User": u.username, **kwargs},
        )
    if (admin and not callback):
        return QJR(400, "请求参数错误")
    re = None
    if callback:
        if admin:
            judge, resp = is_admin_request, lambda ret: redirect_to_login(
                callback) if ret == -1 else lambda: render(request, "403.html")
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
    if not is_login(req):
        return -1
    # 优先使用JWT获取用户信息
    if is_login_jwt(req):
        user = get_user_from_jwt(req)
    else:
        user = get_user(req)
    return is_admin(user)


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
            self._access_token = requests.get(
                url, params=wx_key).json()["access_token"]
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


# ====================== JWT 认证工具函数 ======================

@logger.catch
def generate_jwt_token(user):
    """
    为用户生成JWT令牌，密钥使用用户密码，有效期100年

    Args:
        user: User对象

    Returns:
        str: JWT令牌字符串
    """
    try:
        # 使用用户密码作为JWT密钥
        secret_key = user.password

        # 计算100年后的时间戳
        current_time = int(time.time())
        expiry_time = current_time + (JWT_EXPIRY_YEARS * 365 * 24 * 60 * 60)

        # 创建JWT载荷
        payload = {
            'user_id': user.pk,
            'username': user.username,
            'isSuperUser': user.isSuperUser,
            'iat': current_time,  # 签发时间
            'exp': expiry_time,   # 过期时间
            'iss': 'family_tree_app'  # 签发者
        }

        # 生成令牌
        token = jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)
        logger.info(
            f"JWT token generated for user {user.username} (id: {user.pk})")
        return token

    except Exception as e:
        logger.error(
            f"Failed to generate JWT token for user {user.username}: {str(e)}")
        raise


@logger.catch
def verify_jwt_token(token):
    """
    验证JWT令牌

    Args:
        token: JWT令牌字符串

    Returns:
        dict: 载荷信息如果验证成功，None如果失败
    """
    try:
        # 首先尝试从默认Guest用户获取密钥进行验证
        # 这样可以处理旧令牌
        candidates = [Guest.password]

        # 尝试从数据库中所有用户获取可能的密钥
        all_users = User.objects.all()
        for user in all_users:
            if user.password not in candidates:
                candidates.append(user.password)

        # 尝试每个可能的密钥
        for secret_key in candidates:
            try:
                payload = jwt.decode(
                    token, secret_key, algorithms=[JWT_ALGORITHM])
                logger.info(
                    f"JWT token verified successfully for user {payload.get('username')}")
                return payload
            except jwt.ExpiredSignatureError:
                logger.warning("JWT token has expired")
                continue
            except jwt.InvalidTokenError:
                continue
            except Exception as e:
                logger.warning(f"Error verifying JWT token with key: {str(e)}")
                continue

        logger.error("JWT token verification failed with all keys")
        return None

    except Exception as e:
        logger.error(f"JWT token verification error: {str(e)}")
        return None


@logger.catch
def extract_token_from_request(request):
    """
    从HTTP请求中提取JWT令牌

    Args:
        request: Django HTTP请求对象

    Returns:
        str: JWT令牌字符串，如果没有找到则返回None
    """
    # 首先尝试从Authorization头部获取
    auth_header = request.META.get('HTTP_AUTHORIZATION', '')
    if auth_header and auth_header.startswith('Bearer '):
        return auth_header[7:]  # 去掉 'Bearer ' 前缀

    # 尝试从GET参数获取
    token_from_get = request.GET.get('token')
    if token_from_get:
        return token_from_get

    # 尝试从POST参数获取
    token_from_post = request.POST.get('token')
    if token_from_post:
        return token_from_post

    # 尝试从请求体JSON中获取
    try:
        if request.body:
            import json
            body_data = json.loads(request.body.decode())
            token_from_body = body_data.get('token')
            if token_from_body:
                return token_from_body
    except:
        pass

    return None


@logger.catch
def get_user_from_jwt(request):
    """
    从JWT令牌中获取用户信息

    Args:
        request: Django HTTP请求对象

    Returns:
        User对象或None
    """
    token = extract_token_from_request(request)
    if not token:
        logger.warning("No JWT token found in request")
        return None

    payload = verify_jwt_token(token)
    if not payload:
        logger.warning("Invalid JWT token")
        return None

    try:
        user_id = payload.get('user_id')
        username = payload.get('username')

        if user_id and username:
            # 验证用户仍然存在且匹配
            user = User.objects.get(pk=user_id, username=username)
            logger.info(f"User {username} authenticated via JWT token")
            return user
        else:
            logger.warning("Invalid JWT payload")
            return None

    except User.DoesNotExist:
        logger.warning(
            f"User {username} (id: {user_id}) not found in database")
        return None
    except Exception as e:
        logger.error(f"Error getting user from JWT payload: {str(e)}")
        return None


@logger.catch
def is_login_jwt(request):
    """
    检查用户是否通过JWT认证登录

    Args:
        request: Django HTTP请求对象

    Returns:
        bool: True如果用户已登录，False否则
    """
    user = get_user_from_jwt(request)
    return user is not None


@logger.catch
def get_user_jwt(request):
    """
    获取当前用户（优先从JWT，其次从session，最后返回Guest）

    Args:
        request: Django HTTP请求对象

    Returns:
        User对象
    """
    # 首先尝试从JWT获取用户
    user_from_jwt = get_user_from_jwt(request)
    if user_from_jwt:
        return user_from_jwt

    # 如果JWT失败，回退到session
    user = request.session.get("username")
    logger.info(f"{user} {type(user)} called get_user_jwt.")
    if user is None:
        return Guest
    try:
        return User.objects.filter(username=user)[0]
    except Exception:
        logout_(request)
        return Guest
