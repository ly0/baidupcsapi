#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import wraps
import re
import time
import json
import os
import logging
import pickle
import string
import random
import base64
from hashlib import sha1, md5
from urllib import urlencode, quote
from zlib import crc32
from requests_toolbelt import MultipartEncoder
import requests
requests.packages.urllib3.disable_warnings()
import rsa
import urllib


"""
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S')
"""

BAIDUPAN_SERVER = 'pan.baidu.com'
BAIDUPCS_SERVER = 'pcs.baidu.com'
BAIDUPAN_HEADERS = {"Referer": "http://pan.baidu.com/disk/home",
                    "User-Agent": "netdisk;4.6.2.0;PC;PC-Windows;10.0.10240;WindowsBaiduYunGuanJia"}

# https://pcs.baidu.com/rest/2.0/pcs/manage?method=listhost -> baidu cdn
# uses CDN_DOMAIN/monitor.jpg to test speed for each CDN
api_template = 'http://%s/api/{0}' % BAIDUPAN_SERVER


class LoginFailed(Exception):

    """因为帐号原因引起的登录失败异常
    如果是超时则是返回Timeout的异常
    """
    pass

# experimental


class CancelledError(Exception):

    """
    用户取消文件上传
    """

    def __init__(self, msg):
        self.msg = msg
        Exception.__init__(self, msg)

    def __str__(self):
        return self.msg

    __repr__ = __str__


class BufferReader(MultipartEncoder):

    """将multipart-formdata转化为stream形式的Proxy类
    """

    def __init__(self, fields, boundary=None, callback=None, cb_args=(), cb_kwargs={}):
        self._callback = callback
        self._progress = 0
        self._cb_args = cb_args
        self._cb_kwargs = cb_kwargs
        super(BufferReader, self).__init__(fields, boundary)

    def read(self, size=None):
        chunk = super(BufferReader, self).read(size)
        self._progress += int(len(chunk))
        self._cb_kwargs.update({
            'size': self._len,
            'progress': self._progress
        })
        if self._callback:
            try:
                self._callback(*self._cb_args, **self._cb_kwargs)
            except:  # catches exception from the callback
                raise CancelledError('The upload was cancelled.')
        return chunk


def check_login(func):
    """检查用户登录状态
    这是pcs的检查方法
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        if type(ret) == requests.Response:
            try:
                foo = json.loads(ret.content)
                if foo.has_key('errno') and foo['errno'] == -6:
                    logging.debug(
                        'Offline, deleting cookies file then relogin.')
                    path = '.{0}.cookies'.format(args[0].username)
                    if os.path.exists(path):
                        os.remove(path)
                    args[0]._initiate()
            except:
                pass
        return ret
    return wrapper


class BaseClass(object):

    """提供PCS类的基本方法
    """

    def __init__(self, username, password, api_template=api_template, captcha_func=None):
        self.session = requests.session()
        self.api_template = api_template
        self.username = username
        self.password = password
        self.user = {}
        self.progress_func = None
        if captcha_func:
            self.captcha_func = captcha_func
        else:
            self.captcha_func = self.show_captcha
        # 设置pcs服务器
        logging.debug('setting pcs server')
        self.set_pcs_server(self.get_fastest_pcs_server())
        self._initiate()

    def get_fastest_pcs_server_test(self):
        """通过测试返回最快的pcs服务器
        :returns: str -- 服务器地址
        """
        ret = requests.get(
            'https://pcs.baidu.com/rest/2.0/pcs/manage?method=listhost').content
        serverlist = [server['host'] for server in json.loads(ret)['list']]
        url_pattern = 'http://{0}/monitor.jpg'
        time_record = []
        for server in serverlist:
            start = time.time() * 1000
            requests.get(url_pattern.format(server))
            end = time.time() * 1000
            time_record.append((end - start, server))
            logging.info('TEST %s %s ms' % (server, int(end - start)))
        return min(time_record)[1]

    def get_fastest_pcs_server(self):
        """通过百度返回设置最快的pcs服务器
        """
        url = 'http://pcs.baidu.com/rest/2.0/pcs/file?app_id=250528&method=locateupload'
        ret = requests.get(url).content
        foo = json.loads(ret)
        return foo['host']

    def set_pcs_server(self, server):
        """手动设置百度pcs服务器
        :params server: 服务器地址或域名

        .. warning::
            不要加 http:// 和末尾的 /
        """
        global BAIDUPCS_SERVER
        BAIDUPCS_SERVER = server

    def _remove_empty_items(self, data):
        for k, v in data.copy().items():
            if v is None:
                data.pop(k)

    def user_info(self, **kwargs):
        params = {
            'method': "query",
            'reminder': "1",
        }

        url = 'https://pan.baidu.com/rest/2.0/membership/user'
        return self._request('membership/user', 'user', url=url, extra_params=params, **kwargs)

    def _initiate(self):
        if not self._load_cookies():
            self.session.get('http://www.baidu.com')
            self.user['token'] = self._get_token()
            self._login()
        else:
            self.user['token'] = self._get_token()

    def _save_cookies(self):
        cookies_file = '.{0}.cookies'.format(self.username)
        with open(cookies_file, 'w') as f:
            pickle.dump(
                requests.utils.dict_from_cookiejar(self.session.cookies), f)

    def _load_cookies(self):
        cookies_file = '.{0}.cookies'.format(self.username)
        logging.debug('cookies file:' + cookies_file)
        if os.path.exists(cookies_file):
            logging.debug('%s cookies file has already existed.' %
                          self.username)
            with open(cookies_file) as cookies_file:
                cookies = requests.utils.cookiejar_from_dict(
                    pickle.load(cookies_file))
                logging.debug(str(cookies))
                self.session.cookies = cookies
                self.user['BDUSS'] = self.session.cookies['BDUSS']
                return True
        else:
            return False

    def _get_token(self):
        # Token
        ret = self.session.get(
            'https://passport.baidu.com/v2/api/?getapi&tpl=mn&apiver=v3&class=login&tt=%s&logintype=dialogLogin&callback=0' % int(time.time())).text.replace('\'', '\"')
        foo = json.loads(ret)
        logging.info('token %s' % foo['data']['token'])
        return foo['data']['token']

    def _get_captcha(self, code_string):
        # Captcha
        if code_string:
            verify_code = self.captcha_func("https://passport.baidu.com/cgi-bin/genimage?" + code_string)
        else:
            verify_code = ""

        return verify_code

    def show_captcha(self, url_verify_code):
        print(url_verify_code)
        verify_code = raw_input('open url aboved with your web browser, then input verify code > ')

        return verify_code

    def _get_publickey(self):
        url = 'https://passport.baidu.com/v2/getpublickey?token=' + \
            self.user['token']
        content = self.session.get(url).content
        jdata = json.loads(content.replace('\'','"'))
        return (jdata['pubkey'], jdata['key'])

    def _login(self):
        # Login
        #code_string, captcha = self._get_captcha()
        captcha = ''
        code_string = ''
        pubkey, rsakey = self._get_publickey()
        key = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey)
        password_rsaed = base64.b64encode(rsa.encrypt(self.password, key))
        while True:
            login_data = {'staticpage': 'http://www.baidu.com/cache/user/html/v3Jump.html',
                          'charset': 'UTF-8',
                          'token': self.user['token'],
                          'tpl': 'pp',
                          'subpro': '',
                          'apiver': 'v3',
                          'tt': str(int(time.time())),
                          'codestring': code_string,
                          'isPhone': 'false',
                          'safeflg': '0',
                          'u': 'https://passport.baidu.com/',
                          'quick_user': '0',
                          'logLoginType': 'pc_loginBasic',
                          'loginmerge': 'true',
                          'logintype': 'basicLogin',
                          'username': self.username,
                          'password': password_rsaed,
                          'verifycode': captcha,
                          'mem_pass': 'on',
                          'rsakey': str(rsakey),
                          'crypttype': 12,
                          'ppui_logintime': '50918',
                          'callback': 'parent.bd__pcbs__oa36qm'}
            result = self.session.post(
                'https://passport.baidu.com/v2/api/?login', data=login_data)

            # 是否需要验证码
            if 'err_no=257' in result.content or 'err_no=6' in result.content:
                code_string = re.findall('codeString=(.*?)&', result.content)[0]
                logging.debug('need captcha, codeString=' + code_string)
                captcha = self._get_captcha(code_string)
                continue

            break

        # check exception
        self._check_account_exception(result.content)

        if not result.ok:
            raise LoginFailed('Logging failed.')
        logging.info('COOKIES' + str(self.session.cookies))
        try:
            self.user['BDUSS'] = self.session.cookies['BDUSS']
        except:
            raise LoginFailed('Logging failed.')
        logging.info('user %s Logged in BDUSS: %s' %
                     (self.username, self.user['BDUSS']))
        
        self.user_info()
        self._save_cookies()

    def _check_account_exception(self, content):
        err_id = re.findall('err_no=([\d]+)', content)[0]

        if err_id == '0':
            return
        error_message = {
            '-1':'系统错误, 请稍后重试',
            '1':'您输入的帐号格式不正确',
            '3':'验证码不存在或已过期,请重新输入',
            '4': '您输入的帐号或密码有误',
            '5': '请在弹出的窗口操作,或重新登录',
            '6':'验证码输入错误',
            '16': '您的帐号因安全问题已被限制登录',
            '257': '需要验证码',
            '100005': '系统错误, 请稍后重试',
            '120016': '未知错误 120016',
            '120019': '近期登录次数过多, 请先通过 passport.baidu.com 解除锁定',
            '120021': '登录失败,请在弹出的窗口操作,或重新登录',
            '500010': '登录过于频繁,请24小时后再试',
            '400031': '账号异常，请在当前网络环境下在百度网页端正常登录一次',
            '401007': '您的手机号关联了其他帐号，请选择登录'}
        try:
            msg = error_message[err_id]
        except:
            msg = 'unknown err_id=' + err_id
        raise LoginFailed(msg)

    def _params_utf8(self, params):
        for k, v in params.items():
            if isinstance(v, unicode):
                params[k] = v.encode('utf-8')

    @check_login
    def _request(self, uri, method=None, url=None, extra_params=None,
                 data=None, files=None, callback=None, **kwargs):
        params = {
            'method': method,
            'app_id': "250528",
            'BDUSS': self.user['BDUSS'],
            't': str(int(time.time())),
            'bdstoken': self.user['token']
        }
        if extra_params:
            params.update(extra_params)
            self._remove_empty_items(params)

        headers = dict(BAIDUPAN_HEADERS)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
            kwargs.pop('headers')

        self._params_utf8(params)
        if not url:
            url = self.api_template.format(uri)
        if data or files:

            if '?' in url:
                api = "%s&%s" % (url, urlencode(params))
            else:
                api = '%s?%s' % (url, urlencode(params))

            # print params
            if data:
                self._remove_empty_items(data)
                response = self.session.post(api, data=data, verify=False,
                                             headers=headers, **kwargs)
            else:
                self._remove_empty_items(files)

                body = BufferReader(files, callback=callback)
                headers.update({
                    "Content-Type": body.content_type
                }
                )

                response = self.session.post(
                    api, data=body, verify=False, headers=headers, **kwargs)
        else:
            api = url
            if uri == 'filemanager' or uri == 'rapidupload' or uri == 'filemetas' or uri == 'precreate':
                response = self.session.post(
                    api, params=params, verify=False, headers=headers, **kwargs)
            else:
                response = self.session.get(
                    api, params=params, verify=False, headers=headers, **kwargs)
        return response


class PCS(BaseClass):

    def __init__(self,  username, password, captcha_callback=None):
        """
        :param username: 百度网盘的用户名
        :type username: str

        :param password: 百度网盘的密码
        :type password: str

        :param captcha_callback: 验证码的回调函数
        
            .. note::
                该函数会获得一个jpeg文件的内容，返回值需为验证码
        """
        super(PCS, self).__init__(username, password, api_template, captcha_func=captcha_callback)

    def __err_handler(self, act, errno, callback=None, args=(), kwargs={}):
        """百度网盘下载错误控制
        :param act: 出错时的行为, 有 download
        :param errno: 出错时的errno,这个要配合act才有实际意义
        :param callback: 返回时的调用函数, 为空时返回None
        :param args: 给callback函数的参数tuple
        :param kwargs: 给callback函数的带名参数字典

        在本函数调用后一定可以解决提交过来的问题, 在外部不需要重复检查是否存在原问题
        """
        errno = int(errno)

        def err_handler_download():
            if errno == 112:
                # 页面失效, 重新刷新页面
                url = 'http://pan.baidu.com/disk/home'
                self.session.get(url)

            return

        def err_handler_upload():
            # 实际出问题了再写
            return

        def err_handler_generic():
            return

        _act = {'download': err_handler_download,
                'upload': err_handler_upload,
                'generic': err_handler_generic
                }

        if act not in _act:
            raise Exception('行为未定义, 无法处理该行为的错误')

        if callback:
            return callback(*args, **kwargs)
        return None

    def quota(self, **kwargs):
        """获得配额信息
        :return requests.Response

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"errno":0,"total":配额字节数,"used":已使用字节数,"request_id":请求识别号}
        """
        return self._request('quota', **kwargs)

    def upload(self, dir, file_handler, filename, ondup="newcopy", callback=None, **kwargs):
        """上传单个文件（<2G）.

        | 百度PCS服务目前支持最大2G的单个文件上传。
        | 如需支持超大文件（>2G）的断点续传，请参考下面的“分片文件上传”方法。

        :param dir: 网盘中文件的保存路径（不包含文件名）。
                            必须以 / 开头。

                            .. warning::
                                * 注意本接口的 dir 参数不包含文件名，只包含路径
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :param file_handler: 上传文件对象 。(e.g. ``open('foobar', 'rb')`` )

                            .. warning::
                                注意不要使用 .read() 方法.
        :type file_handler: file
        :param callback: 上传进度回调函数
            需要包含 size 和 progress 名字的参数

        :param filename:

        :param ondup: （可选）

                      * 'overwrite'：表示覆盖同名文件；
                      * 'newcopy'：表示生成文件副本并进行重命名，命名规则为“
                        文件名_日期.后缀”。
        :return: requests.Response 对象

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"path":"服务器文件路径","size":文件大小,"ctime":创建时间,"mtime":修改时间,"md5":"文件md5值","fs_id":服务器文件识别号,"isdir":是否为目录,"request_id":请求识别号}

        """

        params = {
            'dir': dir,
            'ondup': ondup,
            'filename': filename
        }

        tmp_filename = ''.join(random.sample(string.ascii_letters, 10))
        files = {'file': (tmp_filename, file_handler)}

        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'upload', url=url, extra_params=params,
                             files=files, callback=callback, **kwargs)

    def upload_tmpfile(self, file_handler, callback=None, **kwargs):
        """分片上传—文件分片及上传.

        百度 PCS 服务支持每次直接上传最大2G的单个文件。

        如需支持上传超大文件（>2G），则可以通过组合调用分片文件上传的
        ``upload_tmpfile`` 方法和 ``upload_superfile`` 方法实现：

        1. 首先，将超大文件分割为2G以内的单文件，并调用 ``upload_tmpfile``
           将分片文件依次上传；
        2. 其次，调用 ``upload_superfile`` ，完成分片文件的重组。

        除此之外，如果应用中需要支持断点续传的功能，
        也可以通过分片上传文件并调用 ``upload_superfile`` 接口的方式实现。

        :param file_handler: 上传文件对象 。(e.g. ``open('foobar', 'rb')`` )

                            .. warning::
                                注意不要使用 .read() 方法.
        :type file_handler: file

        :param callback: 上传进度回调函数
            需要包含 size 和 progress 名字的参数

        :param ondup: （可选）

                      * 'overwrite'：表示覆盖同名文件；
                      * 'newcopy'：表示生成文件副本并进行重命名，命名规则为“
                        文件名_日期.后缀”。
        :type ondup: str

        :return: requests.Response

            .. note::
                这个对象的内容中的 md5 字段为合并文件的凭依

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"md5":"片段的 md5 值","request_id":请求识别号}



        """

        params = {
            'type': 'tmpfile'
        }
        files = {'file': (str(int(time.time())), file_handler)}
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'upload', url=url, extra_params=params, callback=callback,
                             files=files, **kwargs)

    def upload_superfile(self, remote_path, block_list, ondup="newcopy", **kwargs):
        """分片上传—合并分片文件.

        与分片文件上传的 ``upload_tmpfile`` 方法配合使用，
        可实现超大文件（>2G）上传，同时也可用于断点续传的场景。

        :param remote_path: 网盘中文件的保存路径（包含文件名）。
                            必须以  开头。

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :param block_list: 子文件内容的 MD5 值列表；子文件至少两个，最多1024个。
        :type block_list: list
        :param ondup: （可选）

                      * 'overwrite'：表示覆盖同名文件；
                      * 'newcopy'：表示生成文件副本并进行重命名，命名规则为“
                        文件名_日期.后缀”。
        :return: Response 对象

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"path":"服务器文件路径","size":文件大小,"ctime":创建时间,"mtime":修改时间,"md5":"文件md5值","fs_id":服务器文件识别号,"isdir":是否为目录,"request_id":请求识别号}

        """

        params = {
            'path': remote_path,
            'ondup': ondup
        }
        data = {
            'param': json.dumps({'block_list': block_list}),
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'createsuperfile', url=url, extra_params=params,
                             data=data, **kwargs)

    def get_sign(self):
        # refered:
        # https://github.com/PeterDing/iScript/blob/master/pan.baidu.com.py
        url = 'http://pan.baidu.com/disk/home'
        r = self.session.get(url)
        html = r.content
        sign1 = re.search(r'"sign1":"([A-Za-z0-9]+)"', html).group(1)
        sign3 = re.search(r'"sign3":"([A-Za-z0-9]+)"', html).group(1)
        timestamp = re.search(r'"timestamp":([0-9]+)[^0-9]', html).group(1)

        def sign2(j, r):
            a = []
            p = []
            o = ''
            v = len(j)

            for q in xrange(256):
                a.append(ord(j[q % v]))
                p.append(q)

            u = 0
            for q in xrange(256):
                u = (u + p[q] + a[q]) % 256
                t = p[q]
                p[q] = p[u]
                p[u] = t

            i = 0
            u = 0
            for q in xrange(len(r)):
                i = (i + 1) % 256
                u = (u + p[i]) % 256
                t = p[i]
                p[i] = p[u]
                p[u] = t
                k = p[((p[i] + p[u]) % 256)]
                o += chr(ord(r[q]) ^ k)

            return base64.b64encode(o)

        self.dsign = sign2(sign3, sign1)
        self.timestamp = timestamp

    def _locatedownload(self, remote_path, **kwargs):
        """百度云管家获得方式
        :param remote_path: 需要下载的文件路径
        :type remote_path: str
        """
        params = {
            'path': remote_path
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'locatedownload', url=url,
                             extra_params=params, **kwargs)

    def _yunguanjia_format(self, remote_path, **kwargs):
        ret = self._locatedownload(remote_path, **kwargs).content
        data = json.loads(ret)
        return 'http://' + data['host'] + data['path']

    def download_url(self, remote_path, **kwargs):
        """返回目标文件可用的下载地址
        :param remote_path: 每一项代表需要下载的文件路径
        :type remote_path: str list
        """

        def get_url(dlink):
            return self.session.get(dlink,
                                    headers=BAIDUPAN_HEADERS,
                                    stream=True).url

        if not hasattr(self, 'dsign'):
            self.get_sign()

        if isinstance(remote_path, str) or isinstance(remote_path, unicode):
            remote_path = [remote_path]

        file_list = []
        jdata = json.loads(self.meta(remote_path).content)
        if jdata['errno'] != 0:
            jdata = self.__err_handler('generic', jdata['errno'],
                                       self.meta,
                                       args=(remote_path,)
                                       )
        logging.debug('[*]' + str(jdata))
        for i, entry in enumerate(jdata['info']):
            url = entry['dlink']
            foo = get_url(url)
            if 'wenxintishi' in foo:
                file_list.append(self._yunguanjia_format(remote_path[i]))
            else:
                file_list.append(get_url(entry['dlink']))

        return file_list

    def save_album_file(self, album_id, from_uk, save_path, fsid_list):
        data = {
            "from_uk": from_uk,
            "album_id": album_id,
            "to_path": save_path,
            "fsid_list": fsid_list}
        url = "http://pan.baidu.com/pcloud/album/transfertask/create"
        print (self._request(None, data=data, url=url).content)

    def _verify_shared_file(self, shareid, uk, password):
        data = {
            "pwd": password,
            "vcode": "",
            "vcode_str": "",
            "shareid": shareid,
            "uk": uk
        }
        url = "http://pan.baidu.com/share/verify?shareid="+shareid+"&uk="+uk
        return json.loads(self._request(None, data=data, url=url).content)

    def _save_shared_file_list(self, shareid, uk, path, file_list):
        url = "http://pan.baidu.com/share/transfer?shareid="+shareid+"&from="+uk
        data = {
            "filelist": json.dumps(file_list),
            "path": path
        }
        return json.loads(self._request(None, url=url, data=data).content)

    def save_share_list(self, url, path, password=None, filter_callback=None):
        """ 保存分享文件列表到自己的网盘, 支持密码, 支持文件过滤的回调函数
        :param url: 分享的url
        :type url: str

        :param path 保存到自己网盘的位置
        :type path: str

        :param password 分享密码, 如果没有分享资源没有密码则不用填
        :type password: str

        :param filter_callback 过滤文件列表中文件的回调函数, filter(file), 返回值是假值则被过滤掉
        file = {
            "filename": "xxx",
            "size": 1234,
            "isdir": 0
        }
        :return
        {
            "error": 0, # 无错误为0, 否则出错.
            "result": [] # 如果成功会返回添加到自己网盘的文件列表
        }

        context是从分享页面的html中提取的json, 里面保存了分享文件列表
        暂时有用的是file_list, uk, shareid
        context = {
            "typicalPath": "\/\u65b0\u5efa\u6587\u4ef6\u5939(1)\/[SumiSora][Yosuga_no_Sora][BDRip][BIG5][720P]",
            "self": false,
            "username": "",
            "photo": "http:\/\/himg.bdimg.com\/sys\/portrait\/item\/0237bb1b.jpg",
            "uk": 924798052,
            "ctime": 1455779404,
            "flag": 2,
            "linkusername": "cls1010123",
            "vCnt": 118442,
            "tCnt": 27916,
            "dCnt": 12006,
            "file_list": {
                "errno": 0,
                "list": [{
                    "fs_id": 882212291049391,
                    "app_id": "250528",
                    "parent_path": "%2F%E6%96%B0%E5%BB%BA%E6%96%87%E4%BB%B6%E5%A4%B9%281%29",
                    "server_filename": "[SumiSora][Yosuga_no_Sora][BDRip][BIG5][720P]",
                    "size": 0,
                    "server_mtime": 1455779174,
                    "server_ctime": 1455779174,
                    "local_mtime": 1455779174,
                    "local_ctime": 1455779174,
                    "isdir": 1,
                    "isdelete": "0",
                    "status": "0",
                    "category": 6,
                    "share": "0",
                    "path_md5": "18281300157632491061",
                    "delete_fs_id": "0",
                    "extent_int3": "0",
                    "extent_tinyint1": "0",
                    "extent_tinyint2": "0",
                    "extent_tinyint3": "0",
                    "extent_tinyint4": "0",
                    "path": "\/\u65b0\u5efa\u6587\u4ef6\u5939(1)\/[SumiSora][Yosuga_no_Sora][BDRip][BIG5][720P]",
                    "root_ns": 465254146,
                    "md5": "",
                    "file_key": ""
                }]
            },
            "loginstate": 0,
            "channel": 4,
            "third_url": 0,
            "bdstoken": null ,
            "sampling": {
                "expvar": ["chengyong"]
            },
            "is_vip": 0,
            "description": "",
            "shorturl": "1skhBegP",
            "shareinfo": "",
            "is_baiduspider": 0,
            "isinwhitelist": 0,
            "public": 0,
            "shareid": 23915657,
            "bj_unicom": 0,
            "visitor_uk": null ,
            "visitor_avatar": null ,
            "timestamp": 1458198232,
            "sign": "xxxx",
            "sekey": "xxxx",
            "novelid": false,
            "is_master_vip": 0,
            "urlparam": [],
            "XDUSS": "null"
        }
        """
        # 这里无论是短链接还是长链接如果带密码, 则都被重定向到长链接, 可以直接取出shareid, uk
        # 而如果是不带密码的分享, 则此时还不需要shareid,uk
        respond = self._request(None, url=url)

        target_url = respond.url
        shareid, uk = None, None
        m = re.search(r"shareid=(\d+)", target_url)
        if m:
            shareid = m.group(1)
        m = re.search(r"uk=(\d+)", target_url)
        if m:
            uk = m.group(1)

        # 检查验证码, 如果成功, 当前用户就被授权直接访问资源了
        if password:
            verify_result = self._verify_shared_file(shareid, uk, password)
            if not verify_result or verify_result['errno'] != 0:
                return verify_result

        # 从html中解析文件列表, 同时把shareid, uk也解析出来
        html = self._request(None, url=target_url).content
        r = re.compile(r".*_context =(.*);.*")
        m = r.search(html)
        if m:
            context = json.loads(m.group(1))
            file_list = context['file_list']['list']
            uk = str(context['uk'])
            shareid = str(context['shareid'])
            ret = {"filelist": []}
            for f in file_list:
                file_obj = {
                    'filename': f['server_filename'],
                    'size': f['size'],
                    'isdir': f['isdir']
                }
                if not filter_callback or filter_callback(file_obj):
                    ret['filelist'].append(f['path'])
            save_share_file_ret = self._save_shared_file_list(shareid, uk, path, ret['filelist'])
            if save_share_file_ret and save_share_file_ret['errno'] == 0:
                return save_share_file_ret
            else:
                return ret
        else:
            # 获取文件列表失败
            return {"errno": -1, "error_msg": "PCS.save_share_list failed, mayby url is incorrect!"}

    # Deprecated
    # using download_url to get real download url
    def download(self, remote_path, **kwargs):
        """下载单个文件。

        download 接口支持HTTP协议标准range定义，通过指定range的取值可以实现
        断点下载功能。 例如：如果在request消息中指定“Range: bytes=0-99”，
        那么响应消息中会返回该文件的前100个字节的内容；
        继续指定“Range: bytes=100-199”，
        那么响应消息中会返回该文件的第二个100字节内容::

          >>> headers = {'Range': 'bytes=0-99'}
          >>> pcs = PCS('username','password')
          >>> pcs.download('/test_sdk/test.txt', headers=headers)

        :param remote_path: 网盘中文件的路径（包含文件名）。
                            必须以 / 开头。

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :return: requests.Response 对象
        """

        params = {
            'path': remote_path,
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'download', url=url,
                             extra_params=params, **kwargs)

    def get_streaming(self, path, stype="M3U8_AUTO_480", **kwargs):
        """获得视频的m3u8列表

        :param path: 视频文件路径
        :param type: 返回stream类型, 已知有``M3U8_AUTO_240``/``M3U8_AUTO_480``/``M3U8_AUTO_720``

            .. warning::
                M3U8_AUTO_240会有问题, 目前480P是最稳定的, 也是百度网盘默认的
        :return: str 播放(列表)需要的信息
        """

        params = {
            'path': path,
            'type': stype
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        while True:
            ret = self._request('file', 'streaming', url=url, extra_params=params, **kwargs)
            if not ret.ok:
                logging.debug('get_streaming ret_status_code %s' % ret.status_code)
                jdata = json.loads(ret.content)
                if jdata['error_code'] == 31345:
                    # 再试一次
                    continue
                elif jdata['error_code'] == 31066:
                    # 文件不存在
                    return 31066
                elif jdata['error_code'] == 31304:
                    # 文件类型不支持
                    return 31304
                elif jdata['error_code'] == 31023:
                    # params error
                    return 31023
            return ret.content
 
    def mkdir(self, remote_path, **kwargs):
        """为当前用户创建一个目录.

        :param remote_path: 网盘中目录的路径，必须以 / 开头。

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :return: Response 对象

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"fs_id":服务器文件识别号,"path":"路径","ctime":创建时间,"mtime":修改时间,"status":0,"isdir":1,"errno":0,"name":"文件路径"}

        """

        data = {
            'path': remote_path,
            'isdir': "1",
            "size": "",
            "block_list": "[]"
        }
        # 奇怪的是创建新目录的method是post
        return self._request('create', 'post', data=data, **kwargs)

    def list_files(self, remote_path, by="name", order="desc",
                   limit=None, **kwargs):
        """获取目录下的文件列表.

        :param remote_path: 网盘中目录的路径，必须以 / 开头。

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :param by: 排序字段，缺省根据文件类型排序：

                   * time（修改时间）
                   * name（文件名）
                   * size（大小，注意目录无大小）
        :param order: “asc”或“desc”，缺省采用降序排序。

                      * asc（升序）
                      * desc（降序）
        :param limit: 返回条目控制，参数格式为：n1-n2。

                      返回结果集的[n1, n2)之间的条目，缺省返回所有条目；
                      n1从0开始。
        :return: requests.Response 对象

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {
                    "errno":0,
                    "list":[
                        {"fs_id":服务器文件识别号"path":"路径","server_filename":"服务器文件名（不汗含路径）","size":文件大小,"server_mtime":服务器修改时间,"server_ctime":服务器创建时间,"local_mtime":本地修改时间,"local_ctime":本地创建时间,"isdir":是否是目录,"category":类型,"md5":"md5值"}……等等
                           ],
                    "request_id":请求识别号
                }

        """
        if order == "desc":
            desc = "1"
        else:
            desc = "0"

        params = {
            'dir': remote_path,
            'order': by,
            'desc': desc
        }
        return self._request('list', 'list', extra_params=params, **kwargs)

    def move(self, path_list, dest, **kwargs):
        """
        移动文件或文件夹

        :param path_list: 在百度盘上要移动的源文件path
        :type path_list: list

        :param dest: 要移动到的目录
        :type dest: str

        """
        def __path(path):
            if path.endswith('/'):
                return path.split('/')[-2]
            else:
                return os.path.basename(path)
        params = {
            'opera': 'move'
        }
        data = {
            'filelist': json.dumps([{
                "path": path,
                "dest": dest,
                "newname": __path(path)} for path in path_list]),
        }
        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'move', url=url, data=data, extra_params=params, **kwargs)

    def rename(self, rename_pair_list, **kwargs):
        """重命名

        :param rename_pair_list: 需要重命名的文件(夹)pair （路径，新名称）列表,如[('/aa.txt','bb.txt')]
        :type rename_pair_list: list

        """
        foo = []
        for path, newname in rename_pair_list:
            foo.append({'path': path,
                        'newname': newname
                        })

        data = {'filelist': json.dumps(foo)}
        params = {
            'opera': 'rename'
        }

        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        print '请求url', url
        logging.debug('rename ' + str(data) + 'URL:' + url)
        return self._request('filemanager', 'rename', url=url, data=data, extra_params=params, **kwargs)

    def copy(self, path_list, dest, **kwargs):
        """
        复制文件或文件夹

        :param path_list: 在百度盘上要复制的源文件path
        :type path_list: list

        :param dest: 要复制到的目录
        :type dest: str

        """
        def __path(path):
            if path.endswith('/'):
                return path.split('/')[-2]
            else:
                return os.path.basename(path)
        params = {
            'opera': 'copy'
        }
        data = {
            'filelist': json.dumps([{
                "path": path,
                "dest": dest,
                "newname": __path(path)} for path in path_list]),
        }
        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'move', url=url, data=data, extra_params=params, **kwargs)

    def delete(self, path_list, **kwargs):
        """
        删除文件或文件夹

        :param path_list: 待删除的文件或文件夹列表,每一项为服务器路径
        :type path_list: list


        """
        data = {
            'filelist': json.dumps([path for path in path_list])
        }
        url = 'http://{0}/api/filemanager?opera=delete'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'delete', url=url, data=data, **kwargs)

    def share(self, file_ids, pwd=None, **kwargs):
        """
        创建一个文件的分享链接

        :param file_ids: 要分享的文件fid列表
        :type path_list: list

        :param pwd: 分享密码，没有则没有密码
        :type pwd: str

        :return: requests.Response 对象

            .. note::
                返回正确
                    {
                        "errno": 0,

                        "request_id": 请求识别号,

                        "shareid": 分享识别号,

                        "link": "分享地址",

                        "shorturl": "段网址",

                        "ctime": 创建时间,

                        "premis": false
                    }

        """
        if pwd:
            data = {
                'fid_list': json.dumps([int(fid) for fid in file_ids]),
                'pwd': pwd,
                'schannel': 4,
                'channel_list': json.dumps([])
            }
        else:
            data = {
                'fid_list': json.dumps([int(fid) for fid in file_ids]),
                'schannel': 0,
                'channel_list': json.dumps([])
            }
        url = 'http://pan.baidu.com/share/set'
        return self._request('share/set', '', url=url, data=data, **kwargs)

    def list_streams(self, file_type, start=0, limit=1000, order='time', desc='1',
                     filter_path=None, **kwargs):
        """以视频、音频、图片及文档四种类型的视图获取所创建应用程序下的
        文件列表.

        :param file_type: 类型分为video audio image doc other exe torrent
        :param start: 返回条目控制起始值，缺省值为0。
        :param limit: 返回条目控制长度，缺省为1000，可配置。
        :param filter_path: 需要过滤的前缀路径，如：/album

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :return: requests.Response 对象, 结构和 list_files 相同
        """
        if file_type == 'doc':
            file_type = '4'
        elif file_type == 'video':
            file_type = '1'
        elif file_type == 'image':
            file_type = '3'
        elif file_type == 'torrent':
            file_type = '7'
        elif file_type == 'other':
            file_type = '6'
        elif file_type == 'audio':
            file_type = '2'
        elif file_type == 'exe':
            file_type = '5'

        params = {
            'category': file_type,
            'pri': '-1',
            'start': start,
            'num': limit,
            'order': order,
            'desc': desc,
            'filter_path': filter_path,
        }
        url = 'http://pan.baidu.com/api/categorylist'
        return self._request('categorylist', 'list', url=url, extra_params=params,
                             **kwargs)

    def add_download_task(self, source_url, remote_path, selected_idx=(), **kwargs):
        """
        添加离线任务，支持所有百度网盘支持的类型
        """
        if source_url.startswith('magnet:?'):
            print('Magnet: "%s"' % source_url)
            return self.add_magnet_task(source_url, remote_path, selected_idx, **kwargs)
        elif source_url.endswith('.torrent'):
            print('BitTorrent: "%s"' % source_url)
            return self.add_torrent_task(source_url, remote_path, selected_idx, **kwargs)
        else:
            print('Others: "%s"' % source_url)
            data = {
                'method': 'add_task',
                'source_url': source_url,
                'save_path': remote_path,
            }
            url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
            return self._request('services/cloud_dl', 'add_task', url=url,
                                 data=data, **kwargs)

    def add_torrent_task(self, torrent_path, save_path='/', selected_idx=(), **kwargs):
        """
        添加本地BT任务

        :param torrent_path: 本地种子的路径

        :param save_path: 远程保存路径

        :param selected_idx: 要下载的文件序号 —— 集合为空下载所有，非空集合指定序号集合，空串下载默认

        :return: requests.Response

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                {"task_id":任务编号,"rapid_download":是否已经完成（急速下载）,"request_id":请求识别号}

        """

        # 上传种子文件
        torrent_handler = open(torrent_path, 'rb')
        basename = os.path.basename(torrent_path)

        # 清理同名文件
        self.delete(['/' + basename])

        response = self.upload('/', torrent_handler, basename).json()
        remote_path = response['path']
        logging.debug('REMOTE PATH:' + remote_path)

        # 获取种子信息
        response = self._get_torrent_info(remote_path).json()
        if response.get('error_code'):
            print(response.get('error_code'))
            return
        if not response['torrent_info']['file_info']:
            return

        # 要下载的文件序号：集合为空下载所有，非空集合指定序号集合，空串下载默认
        if isinstance(selected_idx, (tuple, list, set)):
            if len(selected_idx) > 0:
                selected_idx = ','.join(map(str, selected_idx))
            else:
                selected_idx = ','.join(map(str, range(1, len(response['torrent_info']['file_info']) + 1)))
        else:
            selected_idx = ''

        # 开始下载
        data = {
            'file_sha1': response['torrent_info']['sha1'],
            'save_path': save_path,
            'selected_idx': selected_idx,
            'task_from': '1',
            'source_path': remote_path,
            'type': '2'  # 2 is torrent file
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('create', 'add_task', url=url, data=data, **kwargs)

    def _get_torrent_info(self, torrent_path):
        data = {
            'source_path': torrent_path,
            'type': '2'  # 2 is torrent
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('cloud_dl', 'query_sinfo', url=url, data=data, timeout=30)

    def add_magnet_task(self, magnet, remote_path, selected_idx=(), **kwargs):
        response = self._get_magnet_info(magnet).json()
        if response.get('error_code'):
            print(response.get('error_code'))
            return
        if not response['magnet_info']:
            return

        # 要下载的文件序号：集合为空下载所有，非空集合指定序号集合，空串下载默认
        if isinstance(selected_idx, (tuple, list, set)):
            if len(selected_idx) > 0:
                selected_idx = ','.join(map(str, selected_idx))
            else:
                selected_idx = ','.join(map(str, range(1, len(response['magnet_info']) + 1)))
        else:
            selected_idx = ''

        data = {
            'source_url': magnet,
            'save_path': remote_path,
            'selected_idx': selected_idx,
            'task_from': '1',
            'type': '4'  # 4 is magnet
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('create', 'add_task', url=url, data=data, timeout=30)

    def _get_magnet_info(self, magnet):
        data = {
            'source_url': magnet,
            'save_path': '/',
            'type': '4'  # 4 is magnet
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('cloud_dl', 'query_magnetinfo', url=url, data=data, timeout=30)

    def query_download_tasks(self, task_ids, operate_type=1, **kwargs):
        """根据任务ID号，查询离线下载任务信息及进度信息。

        :param task_ids: 要查询的任务 ID字符串 列表
        :type task_ids: list or tuple
        :param operate_type:
                            * 0：查任务信息
                            * 1：查进度信息，默认为1

        :return: requests.Response

            .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                给出一个范例

                {
                    "task_info":
                        {"70970481":{
                                "status":"0",

                                "file_size":"122328178",

                                "finished_size":"122328178",

                                "create_time":"1391620757",

                                "start_time":"1391620757",

                                "finish_time":"1391620757",

                                "save_path":"\/",

                                "source_url":"\/saki-nation04gbcn.torrent",

                                "task_name":"[KTXP][Saki-National][04][GB_CN][720p]",

                                "od_type":"2",

                                "file_list":[
                                    {
                                        "file_name":"[KTXP][Saki-National][04][GB_CN][720p].mp4",

                                        "file_size":"122328178"
                                    }
                                ],

                                "result":0

                                }
                        },

                        "request_id":861570268

                }


        """

        params = {
            'task_ids': ','.join(map(str, task_ids)),
            'op_type': operate_type,
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'query_task', url=url,
                             extra_params=params, **kwargs)

    def download_tasks_number(self):
        """获取离线任务总数

        :return: int
        """
        ret = self.list_download_tasks().content
        foo = json.loads(ret)
        return foo['total']

    def list_download_tasks(self, need_task_info="1", asc="0", start=0, create_time=None, limit=1000, status="255", source_url=None, remote_path=None, **kwargs):
        """查询离线下载任务ID列表及任务信息.

        :param need_task_info: 是否需要返回任务信息:
                               * 0：不需要
                               * 1：需要，默认为1
        :param start: 查询任务起始位置，默认为0。
        :param limit: 设定返回任务数量，默认为10。
        :param asc:
                   * 0：降序，默认值
                   * 1：升序
        :param create_time: 任务创建时间，默认为空。
        :type create_time: int
        :param status: 任务状态，默认为空。

            .. note::
                任务状态有
                       0:下载成功

                       1:下载进行中

                       2:系统错误

                       3:资源不存在

                       4:下载超时

                       5:资源存在但下载失败

                       6:存储空间不足

                       7:目标地址数据已存在, 8:任务取消.
        :type status: int
        :param source_url: 源地址URL，默认为空。
        :param remote_path: 文件保存路径，默认为空。

                            .. warning::
                                * 路径长度限制为1000；
                                * 径中不能包含以下字符：``\\\\ ? | " > < : *``；
                                * 文件名或路径名开头结尾不能是 ``.``
                                  或空白字符，空白字符包括：
                                  ``\\r, \\n, \\t, 空格, \\0, \\x0B`` 。
        :param expires: 请求失效时间，如果有，则会校验。
        :type expires: int
        :return: Response 对象

             .. note::
                返回正确时返回的 Reponse 对象 content 中的数据结构

                    {
                        "task_info": [

                            {

                                "task_id": "任务识别号",

                                "od_type": "2",

                                "source_url": "原地址，bt任务为种子在服务器上的路径，否则为原始URL",

                                "save_path": "保存路径",

                                "rate_limit": "速度限制，0为不限",

                                "timeout": "0",

                                "callback": "",

                                "status": "任务状态",

                                "create_time": "创建时间",

                                "task_name": "任务名"

                            },……等等

                        ],

                        "total": 总数,

                        "request_id": 请求识别号

                    }
        """

        params = {
            'start': start,
            'limit': limit,
            'status': status,
            'need_task_info': need_task_info,
            'asc': asc,
            'source_url': source_url,
            'remote_path': remote_path,
            'create_time': create_time

        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'list_task', url=url, extra_params=params, **kwargs)

    def cancel_download_task(self, task_id, expires=None, **kwargs):
        """取消离线下载任务.

        :param task_id: 要取消的任务ID号。
        :type task_id: str
        :param expires: 请求失效时间，如果有，则会校验。
        :type expires: int
        :return: requests.Response
        """

        data = {
            'expires': expires,
            'task_id': task_id,
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'cancel_task', url=url,
                             data=data, **kwargs)

    def list_recycle_bin(self, order="time", desc="1", start=0, limit=1000, page=1, **kwargs):
        # Done
        """获取回收站中的文件及目录列表.

        :param start: 返回条目的起始值，缺省值为0
        :param limit: 返回条目的长度，缺省值为1000
        :return: requests.Response

            格式同 list_files
        """

        params = {
            'start': start,
            'num': limit,
            'dir': '/',
            'order': order,
            'desc': desc
        }
        url = 'http://{0}/api/recycle/list'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'list', url=url, extra_params=params, **kwargs)

    def restore_recycle_bin(self, fs_ids, **kwargs):
        """批量还原文件或目录（非强一致接口，调用后请sleep1秒 ）.

        :param fs_ids: 所还原的文件或目录在 PCS 的临时唯一标识 ID 的列表。
        :type fs_ids: list or tuple
        :return: requests.Response 对象
        """

        data = {
            'fidlist': json.dumps(fs_ids)
        }
        url = 'http://{0}/api/recycle/restore'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'restore', data=data, **kwargs)

    def clean_recycle_bin(self, **kwargs):
        """清空回收站.

        :return: requests.Response
        """

        url = 'http://{0}/api/recycle/clear'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'clear', url=url, **kwargs)

    def rapidupload(self, file_handler, path, **kwargs):
        """秒传一个文件

        :param file_handler: 文件handler, e.g. open('file','rb')
        :type file_handler: file

        :param path: 上传到服务器的路径，包含文件名
        :type path: str

        :return: requests.Response

            .. note::
                * 文件已在服务器上存在，不上传，返回示例
                {

                    "path" : "/apps/album/1.jpg",

                    "size" : 372121,

                    "ctime" : 1234567890,

                    "mtime" : 1234567890,

                    "md5" : "cb123afcc12453543ef",

                    "fs_id" : 12345,

                    "isdir" : 0,

                    "request_id" : 12314124

                }

                * 文件不存在，需要上传

                {"errno":404,"info":[],"request_id":XXX}

                * 文件大小不足 256kb （slice-md5 == content-md5) 时

                {"errno":2,"info":[],"request_id":XXX}

                * 远程文件已存在

                {"errno":-8,"info":[],"request_id":XXX}


        """
        file_handler.seek(0, 2)
        _BLOCK_SIZE = 2 ** 20
        content_length = file_handler.tell()
        file_handler.seek(0)

        # 校验段为前 256kb
        first_256bytes = file_handler.read(256 * 1024)
        slice_md5 = md5(first_256bytes).hexdigest()

        content_crc32 = crc32(first_256bytes).conjugate()
        content_md5 = md5(first_256bytes)

        while True:
            block = file_handler.read(_BLOCK_SIZE)
            if not block:
                break
            # 更新crc32和md5校验值
            content_crc32 = crc32(block, content_crc32).conjugate()
            content_md5.update(block)

        data = {'path': path,
                'content-length': content_length,
                'content-md5': content_md5.hexdigest(),
                'slice-md5': slice_md5,
                'content-crc32': '%d' % (content_crc32.conjugate() & 0xFFFFFFFF)}
        logging.debug('RAPIDUPLOAD DATA ' + str(data))
        #url = 'http://pan.baidu.com/api/rapidupload'
        return self._request('rapidupload', 'rapidupload', data=data, **kwargs)

    def search(self, path, keyword, page=1, recursion=1, limit=1000, **kwargs):
        """搜索文件

        :param path: 搜索目录
        :param keyword: 关键词
        :param page: 返回第几页的数据
        :param recursion: 是否递归搜索，默认为1 （似乎0和1都没影响，都是递归搜索的）
        :param limit: 每页条目

        :return: requests.Repsonse
        返回结果和list_files一样结构
        """
        params = {'dir': path,
                  'recursion': recursion,
                  'key': keyword,
                  'page': page,
                  'num': limit}

        #url = 'http://pan.baidu.com/api/search'

        return self._request('search', 'search', extra_params=params, **kwargs)

    def thumbnail(self, path, height, width, quality=100, **kwargs):
        """获取文件缩略图

        :param path: 远程文件路径
        :param height: 缩略图高
        :param width: 缩略图宽
        :param quality: 缩略图质量，默认100

        :return: requests.Response

            .. note::
                如果返回 HTTP 404 说明该文件不存在缩略图形式
        """
        params = {'ec': 1,
                  'path': path,
                  'quality': quality,
                  'width': width,
                  'height': height}

        url = 'http://{0}/rest/2.0/pcs/thumbnail'.format(BAIDUPCS_SERVER)
        return self._request('thumbnail', 'generate', url=url, extra_params=params, **kwargs)

    def meta(self, file_list, **kwargs):
        """获得文件(s)的metainfo

        :param file_list: 文件路径列表,如 ['/aaa.txt']
        :type file_list: list

        :return: requests.Response
            .. note ::
            示例

            * 文件不存在

            {"errno":12,"info":[{"errno":-9}],"request_id":3294861771}

            * 文件存在
            {
                "errno": 0,

                "info": [

                    {

                        "fs_id": 文件id,

                        "path": "\/\u5c0f\u7c73\/mi2s\u5237recovery.rar",

                        "server_filename": "mi2s\u5237recovery.rar",

                        "size": 8292134,

                        "server_mtime": 1391274570,

                        "server_ctime": 1391274570,

                        "local_mtime": 1391274570,

                        "local_ctime": 1391274570,

                        "isdir": 0,

                        "category": 6,

                        "path_md5": 279827390796736883,

                        "delete_fs_id": 0,

                        "object_key": "84221121-2193956150-1391274570512754",

                        "block_list": [
                            "76b469302a02b42fd0a548f1a50dd8ac"
                        ],

                        "md5": "76b469302a02b42fd0a548f1a50dd8ac",

                        "errno": 0

                    }

                ],

                "request_id": 2964868977

            }

        """
        if not isinstance(file_list, list):
            file_list = [file_list]
        data = {'target': json.dumps(file_list)}

        return self._request('filemetas?blocks=0&dlink=1', 'filemetas', data=data, **kwargs)

    def check_file_blocks(self, path, size, block_list, **kwargs):
        """文件块检查

        :param path: 文件路径
        :param size: 文件大小
        :param block_list: 文件块的列表,注意按文件块顺序
        :type block_list: list

        .. note::
            如果服务器不存在path的文件，则返回中的block_list会等于提交的block_list

        :return: requests.Response
            .. note::
                返回示例
                {
                    "errno": 0,
                    "path": "/18.rar",
                    "request_id": 2462633013,
                    "block_list": [
                        "8da0ac878f3702c0768dc6ea6820d3ff",
                        "3c1eb99b0e64993f38cd8317788a8855"
                    ]
                }

                其中block_list是需要上传的块的MD5



        """

        data = {'path': path,
                'size': size,
                'isdir': 0,
                'block_list': json.dumps(block_list)}

        return self._request('precreate', 'post', data=data, **kwargs)
