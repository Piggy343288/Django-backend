import random
import json
import os
import hashlib
import hmac
import sys
import time
from .QuickDjango import *
from datetime import datetime
from piggySQL.models import PhoneVerify, User
from django.views.decorators.csrf import csrf_exempt
import requests
from .QuickDjango import logger
from typing import List

from alibabacloud_dysmsapi20170525.client import Client as Dysmsapi20170525Client
from alibabacloud_credentials.client import Client as CredentialClient
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_dysmsapi20170525 import models as dysmsapi_20170525_models
from alibabacloud_tea_util import models as util_models
from alibabacloud_tea_util.client import Client as UtilClient


class Sample:
    def __init__(self):
        pass

    @staticmethod
    def create_client() -> Dysmsapi20170525Client:
        """
        使用凭据初始化账号Client
        @return: Client
        @throws Exception
        """
        # 工程代码建议使用更安全的无AK方式，凭据配置方式请参见：https://help.aliyun.com/document_detail/378659.html。
        credential = CredentialClient()
        config = open_api_models.Config(
            credential=credential
        )
        # Endpoint 请参考 https://api.aliyun.com/product/Dysmsapi
        config.endpoint = f'dysmsapi.aliyuncs.com'
        return Dysmsapi20170525Client(config)

    @staticmethod
    def main(phone_number, code) -> None:
        client = Sample.create_client()
        send_sms_request = dysmsapi_20170525_models.SendSmsRequest(
            sign_name='芋仔兴邦',
            template_code='SMS_499140768',
            phone_numbers=phone_number,
            template_param=json.dumps({"code": str(code)})
        )
        runtime = util_models.RuntimeOptions()
        try:
            resp = client.send_sms_with_options(send_sms_request, runtime)
            return (0, json.dumps(resp, default=str, indent=2))
        except Exception as error:
            return (-1, error)

@logger.catch
@use("POST")
def invoke_send_message(request):
    """
    调用发送短信的函数
    :param request: 请求对象，包含手机号和验证码
    :return: 无
    """
    # 处理OPTIONS预检请求
    if request.method == 'OPTIONS':
        return QJR(200, {})
    
    data = json.loads(request.body)
    phone_number = data.get('phone_number')
    if not phone_number:
        return QJR(400, "手机号不能为空")
    if PhoneVerify.objects.filter(phone_number=phone_number).exists():
        return QJR(400, "不允许重复发送验证码")
    hashCode = random.randint(10000000, 99999999)
    verify_code = random.randint(100000, 999999)
    requests.get(f"https://push.spug.cc/send/RZykKralk6jw0lAL?code={verify_code}&number=5&targets={phone_number}")
    # Sample.main(phone_number, verify_code)
    # 保存验证码到数据库
    PhoneVerify.objects.create(
        phone_number=phone_number,
        hashCode=hashCode,
        verify_code=verify_code
    )
    return QJR(200, {"hashCode": hashCode})

def verify_code(requests):
    """
    验证验证码
    :param requests: 请求对象，包含手机号、编号和验证码
    :return: 无
    """
    # 处理OPTIONS预检请求
    if requests.method == 'OPTIONS':
        return QJR(200, {})
    
    data = json.loads(requests.body)

    phone_number = data.get('phone_number')
    hashCode = data.get('hash')
    verify_code = data.get('code')
    if not phone_number or not hashCode or not verify_code:
        return QJR(400, "手机号、编号和验证码不能为空")
    try:
        phone_verify = PhoneVerify.objects.get(phone_number=phone_number, hashCode=hashCode)
    except PhoneVerify.DoesNotExist:
        return QJR(400, "无效的编号")
    if phone_verify.verify_code != verify_code:
        return QJR(400, "验证码错误")
    # 验证通过，删除验证码记录
    phone_verify.delete()
    
    # 获取当前登录用户并将其Verified字段设置为True
    try:
        current_user = get_user(requests)
        # 检查是否是Guest用户
        if hasattr(current_user, 'Verified'):
            current_user.Verified = True
            current_user.save()
    except Exception:
        # 如果获取用户失败，不影响验证结果
        pass
    
    return QJR(200, {"message": "验证成功"})


@csrf_exempt
def connect_user_to_phone(request):
    """
    连接用户与手机号
    
    Args:
        request: HTTP请求对象，需要包含JSON格式的请求体：
            {
                "user_id": 用户ID,
                "phone_number": 手机号
            }
    
    Returns:
        JsonResponse: 操作结果的JSON响应
    """
    # 处理OPTIONS预检请求
    if request.method == 'OPTIONS':
        return JsonResponse({}, status=200)
    
    try:
        # 验证请求方法
        if request.method != 'POST':
            return JsonResponse({
                'status': 'error',
                'message': '需要POST请求'
            }, status=405)
        
        # 解析请求体
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': '请求体必须是有效的JSON格式'
            }, status=400)
        
        # 验证必需参数
        required_fields = ['user_id', 'phone_number']
        for field in required_fields:
            if field not in data:
                return JsonResponse({
                    'status': 'error',
                    'message': f'缺少必需参数: {field}'
                }, status=400)
        
        # 验证手机号格式
        phone_number = data['phone_number']
        if not (len(phone_number) == 11 and phone_number.isdigit()):
            return JsonResponse({
                'status': 'error',
                'message': '手机号格式不正确，请输入11位数字'
            }, status=400)
        
        # 获取用户
        try:
            user = User.objects.get(id=data['user_id'])
        except User.DoesNotExist:
            return JsonResponse({
                'status': 'error',
                'message': '用户不存在'
            }, status=404)
        
        # 检查手机号是否已被其他用户使用
        existing_user = User.objects.filter(phone_number=phone_number).exclude(id=user.id).first()
        if existing_user:
            return JsonResponse({
                'status': 'error',
                'message': '该手机号已被其他用户使用'
            }, status=400)
        
        # 直接更新用户的phone_number字段
        old_phone = user.phone_number
        user.phone_number = phone_number
        user.save()
        
        # 返回成功响应
        return JsonResponse({
            'status': 'success',
            'message': '用户手机号更新成功',
            'data': {
                'user_id': user.id,
                'username': user.username,
                'phone_number': phone_number
            }
        }, status=200)
    
    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': f'更新失败: {str(e)}'
        }, status=500)
