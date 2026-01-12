from .QuickDjango import qrender, use, b64encode
from .QuickDjango import JsonResponse, exist_such_data
from .QuickDjango import get_user, b64decode, get_size
from .QuickDjango import QJR, file_is_image, wx_url, token
from django.urls import path
import hashlib
import os
import requests
import shutil
from json import loads, dumps
from django.http import FileResponse
from piggySQL.models import User, File, delete_user, defaultImg


def Downloadpath(filePath):
    return b64encode(filePath)


def index_netdisk(request):
    siz = get_user(request).OccupiedSpace / 1048576
    return qrender(request, "index_NetDisk.html", siz=round(siz, 2))


class Upload:

    def upload(u, name, _iter, isPrivate, id=None):
        _md5 = hashlib.md5()
        _sha1 = hashlib.sha1()
        fileName = f"./upload/{u.pk}_{name}"
        with open(fileName, "wb") as f:
            for i in _iter:
                f.write(i)
                _md5.update(i)
                _sha1.update(i)
        hash_code = f"{_md5.hexdigest()}_{_sha1.hexdigest()}"
        new_file_name = f"./upload/{u.pk}_{_md5.hexdigest()}_{_sha1.hexdigest()}_{name}"
        shutil.move(fileName, new_file_name)
        u.OccupiedSpace += os.stat(new_file_name).st_size
        if u.OccupiedSpace >= 2 * 1024 ** 3:
            os.unlink(new_file_name)
            return (400, "Limited Space")
        else:
            u.save()        

        if file_is_image(fileName):
            url = f"{wx_url}/wxa/img_sec_check?access_token={token.access_token}"
            file = [["media", open(new_file_name, "rb")]]
            response = requests.post(url, files=file).json()
            if (response["errcode"] == 87014):
                return (202, )

        file = File.objects.create(
            filePath=new_file_name,
            UserFrom=u.pk,
            isPrivate=isPrivate,
            name=name,
            hash_code=hash_code,
            ultimate_hash=hashlib.md5((hash_code + f"_{u}_{token.timestamp}").encode("utf8")).hexdigest()
        )

        return (200, file.ultimate_hash)

    @use("POST")
    def uploadAction(request):
        u = get_user(request)
        name = request.POST.get('filename')
        chunks = request.FILES.get("upload_file").chunks()
        isPrivate = request.POST.get("isPrivate") == "1"
        id = request.GET.get("id", None)
        return QJR(*Upload.upload(u, name, chunks, isPrivate, id))
    
    urls = [
        path('uploadAction/', uploadAction),
    ]


class Download:

    def download(request):
        return Download.fileList(request, File.objects.filter(UserFrom=get_user(request).pk))

    def publics(request):
        QSet = File.objects.filter(isPrivate=False)
        return Download.fileList(request, QSet)

    def fileList(request, FileList):
        Main = dumps([[i.ultimate_hash, i.name] for i in FileList])
        return qrender(request, "Download.html", Content=Main, callback=None)

    @use("GET")
    def downloadAction(request):
        filename = b64decode(request.GET.get("name").replace(" ", "+"))
        # if not exist_such_data(File, filePath=filename):
        #     return QJR(404, "No Such Object")
        filename = filename.split("/")
        fileObj = File.objects.filter(name=filename[-1], UserFrom=filename[2])
        if not fileObj.exists():
            return QJR(404, "文件不存在")
        fileObj = fileObj[0]
        filename = fileObj.filePath
        if not os.path.exists(filename):
            File.objects.get(filePath=filename).delete()
            return QJR(404, "文件不存在")
        if request.GET.get("base64", None) is None:
            return Download.downloadHandle(filename, fileObj.name)
        else:
            return QJR(200, b64encode(open(filename, "rb").read()))

    @use("GET")
    def downloadAction_v2(request):
        fileObj = File.objects.filter(ultimate_hash=request.GET.get("hash"))
        print(fileObj)
        if len(fileObj) > 1:
            raise ValueError("Should be unique.")
        else:
            fileObj = fileObj[0]
        filename = fileObj.filePath
        if request.GET.get("base64", None) is None:
            return Download.downloadHandle(filename, fileObj.name, fileObj)
        else:
            return QJR(200, b64encode(open(filename, "rb").read()))

    def downloadHandle(filename, rawname = None, fileObj=None):
        resp = FileResponse(open(filename, 'rb'))
        resp['Content-Type'] = 'application/octet-stream'
        if rawname is None:
            rawname = filename
        rawname = rawname.encode('utf-8').decode('ISO-8859-1')
        resp['Content-Disposition'] = \
            f'attachment;filename="{rawname}"'
        
        # 根据文件类型设置缓存策略
        if fileObj and hasattr(fileObj, 'isPrivate'):
            if fileObj.isPrivate:
                # 私有文件不设置长期缓存
                resp['Cache-Control'] = 'private, no-cache'
            else:
                # 公有文件设置一年缓存
                from datetime import datetime, timedelta
                expires = datetime.utcnow() + timedelta(days=365)
                resp['Cache-Control'] = 'public, max-age=31536000'  # 一年缓存
                resp['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
                resp['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        else:
            # 未知文件类型，默认设置一年缓存
            from datetime import datetime, timedelta
            expires = datetime.utcnow() + timedelta(days=365)
            resp['Cache-Control'] = 'public, max-age=31536000'  # 一年缓存
            resp['Expires'] = expires.strftime('%a, %d %b %Y %H:%M:%S GMT')
            resp['Last-Modified'] = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        
        return resp

    urls = [
        path('download/', download),
        path('downloadAction/', downloadAction),
        path('downloadAction_v2/', downloadAction_v2),
        path('public/', publics),
    ]


def delete_file(request):
    hash = request.GET.get("hash", None)
    if hash is None:
        return QJR(400, "Empty hash")
    if not exist_such_data(File, ultimate_hash=hash):
        return QJR(404, "No such file!")
    
    user = get_user(request)
    fileObj = File.objects.get(ultimate_hash=hash)
    
    if not have_permission(fileObj, user):
        return QJR(401, "You do not have the permission to delete this file.")
    
    filename = fileObj.filePath
    u.OccupiedSpace -= os.stat(filename).st_size
    u.save()
    os.unlink(filename)
    fileObj.delete()
    return QJR(200, "Deleted")

urls = [
    path("netdisk/", index_netdisk),
    *Upload.urls,
    *Download.urls
]
