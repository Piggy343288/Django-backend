import os
from django.db.models.base import NON_FIELD_ERRORS
from .QuickDjango import qrender, use, QJR, exist_such_data
from .QuickDjango import login_, get_user, JsonResponse
from .QuickDjango import logout_, redirect, valid_username_check
from .QuickDjango import force_login, read_in_chunks, generate_jwt_token
from .QuickDjango import get_user_jwt
from piggySQL.models import User
from hashlib import sha1 as _sha1
import json
from django.urls import path
from .NetDisk import Upload
from loguru import logger
from .utils import compress_user_head_image, is_image_file, validate_image_size


def sha1(x):
    return _sha1(x.encode("utf8")).hexdigest()


AUTO_USERNAME = 0x01


class Users:
    def _get_user_info(u):
        return {
            "username": u.username,
            "head": u.img,
            "pk": u.pk,
            "Verified": u.Verified,
            "connected": False,
            "phone": u.phone_number
        }

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
    @use("POST")
    def register_action(request):
        Map = json.loads(request.body)
        username = Map.get("username", None)
        password = Map.get("password", None)
        phone_number = Map.get("phone_number", None)
        cid = Map.get("uniapp_cid", None)
        return Users.raw_register(request, username, password, phone_number, cid)

    @logger.catch
    def raw_register(request, name, pwd, phone_number, cid):
        logger.info(
            f"register action called with name: {name}, pwd: {pwd}, phone_number: {phone_number}")
        
        try:
            # 验证用户名
            if name != AUTO_USERNAME:
                ok, name = valid_username_check(name)
                if not ok:
                    return QJR(400, name)
                if User.objects.filter(username__exact=name).exists():
                    return QJR(400, "用户名已存在。")
            
            # 检查手机号是否已存在
            if User.objects.filter(phone_number=phone_number).exists():
                logger.warning(f"注册失败：手机号 {phone_number} 已被使用")
                return QJR(400, "该手机号已被注册，请使用其他手机号或直接登录")
            
            # 创建用户
            login_(request, name)
            u = User.objects.create(username=name, password=sha1(
                pwd), phone_number=phone_number, uniapp_cid=cid)
            
            if name == AUTO_USERNAME:
                u.username = f"新用户 {u.pk}"
                u.save()
            
            token = generate_jwt_token(u)
            return JsonResponse({
                "code": 200,
                "data": Users._get_user_info(u),
                "isSuperUser": int(u.isSuperUser),
                "token": token
            })
            
        except Exception as e:
            logger.error(f"注册过程中发生错误: {str(e)}")
            # 处理唯一约束错误
            if "UNIQUE constraint failed" in str(e):
                if "phone_number" in str(e):
                    return QJR(400, "该手机号已被注册，请使用其他手机号或直接登录")
                elif "username" in str(e):
                    return QJR(400, "用户名已存在，请选择其他用户名")
                else:
                    return QJR(400, "注册信息冲突，请检查输入信息")
            return QJR(500, f"注册失败: {str(e)}")

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
            return QJR(404, "不存在该用户。")
        u = User.objects.get(username=u)
        if u.password == sha1(pwd):
            token = generate_jwt_token(u)
            login_(request, u.username)
            res = {
                "code": 200,
                "data": Users._get_user_info(u),
                "isSuperUser": int(u.isSuperUser),
                "token": token  # 新增JWT令牌字段
            }
            logger.debug(res)
            return JsonResponse(res)
        else:
            return QJR(400, "密码错误。")

    @logger.catch
    @use("GET")
    def user_index_info(request):
        u = get_user(request)
        if u is None:
            return QJR(403, "用户未登录或权限不足")
        name = request.GET.get("UserFrom", u.pk)
        if isinstance(name, str) and not name.isdecimal():
            return QJR(400, "UserFrom参数只能传入整数")
        requested_user = User.objects.filter(pk=name)
        if not requested_user.exists():
            return QJR(404, "用户不存在")
        requested_user = requested_user[0]
        logger.info(f"{u} request user_index_info of {requested_user}")
        Json = Users._get_user_info(requested_user)
        return QJR(200, Json)

    @logger.catch
    @use("GET")
    @force_login()
    def user_info_modify(request):
        user = get_user(request)
        name = request.GET.get("Username", None)
        if len(name) >= 16:
            return QJR(400, "用户名长度超过限制")

        logger.info(f"{user} requested to modify his name to {name}")
        if exist_such_data(User, username=name):
            res = User.objects.get(username=name)
            if res.pk != user.pk:
                logger.warning(
                    f"{user}'s request is not done. Username has already exists: {res}.")
                return QJR(304, "用户名已存在")

        if name:
            user.username = name
        else:
            return QJR(401, "未提供有效的用户名")

        user.save()
        logout_(request)
        return QJR(200)

    @logger.catch
    @use("POST")
    def reset_password(request):
        """
        重设用户密码接口

        请求数据格式：
        {
            "current_password": "原密码",
            "new_password": "新密码"
        }

        功能说明：
        - 验证原密码是否正确
        - 将新密码加密后存入数据库
        - 返回操作结果
        """
        try:
            # 解析请求数据
            if request.content_type == 'application/json':
                data = json.loads(request.body)
            else:
                data = request.POST

            current_password = data.get('current_password')
            new_password = data.get('new_password')

            # 验证输入参数
            if not current_password or not new_password:
                return QJR(400, '原密码和新密码都是必填项')

            if len(new_password) < 6:
                return QJR(400, '新密码长度不能少于6位')

            # 获取当前用户
            current_user = get_user(request)
            if not current_user:
                return QJR(401, '用户未登录')

            # 验证原密码
            current_password_hash = sha1(current_password)
            if current_user.password != current_password_hash:
                logger.warning(f"用户 {current_user.username} 原密码验证失败")
                return QJR(400, '原密码不正确')

            # 检查新密码是否与原密码相同
            new_password_hash = sha1(new_password)
            if current_user.password == new_password_hash:
                return QJR(400, '新密码不能与原密码相同')

            # 更新密码
            current_user.password = new_password_hash
            current_user.save()

            logger.info(f"用户 {current_user.username} 成功重设密码")

            return QJR(200, {
                'message': '密码重设成功',
                'user_id': current_user.pk,
                'username': current_user.username
            })

        except json.JSONDecodeError:
            return QJR(400, '无效的JSON数据')
        except Exception as e:
            logger.error(f"重设密码时发生错误: {str(e)}")
            return QJR(500, f'重设密码失败: {str(e)}')

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
            return QJR(404, "用户不存在")

    @logger.catch
    @use("POST")
    def change_img_action(request):
        u = get_user(request)
        print(u, request)
        # 获取上传的文件
        uploaded_file = request.FILES.get("upload_file")
        if not uploaded_file:
            return QJR(400, "没有上传文件")

        # 验证文件类型
        if not is_image_file(uploaded_file.name):
            return QJR(400, "只支持图片文件格式（jpg, jpeg, png, gif, bmp, webp）")

        # 读取文件数据并验证大小
        try:
            file_data = uploaded_file.read()

            # 验证文件大小（最大10MB）
            if not validate_image_size(file_data, max_file_size_mb=10):
                return QJR(400, "文件大小不能超过10MB")

            # 重新设置文件指针位置（因为前面读取了）
            uploaded_file.seek(0)

        except Exception as e:
            return QJR(400, f"文件读取失败: {str(e)}")

        temp_path = None
        try:
            # 压缩头像
            temp_path = compress_user_head_image(uploaded_file, u.pk)

            # 获取文件内容并上传
            with open(temp_path, 'rb') as temp_file:
                file_content = temp_file.read()

            # 创建一个生成器来模拟文件迭代器
            def file_chunks():
                chunk_size = 1024
                for i in range(0, len(file_content), chunk_size):
                    yield file_content[i:i + chunk_size]

            # 使用原始文件名
            original_filename = uploaded_file.name
            if not original_filename.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                original_filename += '.jpg'

            upload_result = Upload.upload(
                u, original_filename, file_chunks(), False)

            if upload_result[0] == 200:
                # 上传成功，更新用户头像hash值
                u.img = upload_result[1]
                print(upload_result[1], u)
                u.save()
                return QJR(200, u.img)
            else:
                return QJR(500, f"头像上传失败: {upload_result}")

        except Exception as e:
            return QJR(500, f"图片处理失败: {str(e)}")
        finally:
            # 清理临时文件
            if temp_path and os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                except Exception as cleanup_error:
                    print(f"清理临时文件失败: {cleanup_error}")

    urls = [
        path('login/', login),
        path('logout/', logout),
        path('loginAction/', login_action),
        path('register/', register),
        path('registerAction/', register_action),
        path('UserModify/', user_info_modify),
        path('users/reset_password/', reset_password),
        path('user_info/', user_index_info),
        path("exists/", exists),
        path("change_img_action/", change_img_action),
    ]
