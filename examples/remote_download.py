#!/usr/bin/env python
# coding=utf-8

from __future__ import absolute_import, unicode_literals

from hashlib import md5
import functools
import requests
import json
import sys
import os

PACKAGE_PARENT = '..'
SCRIPT_DIR = os.path.dirname(os.path.realpath(os.path.join(os.getcwd(), os.path.expanduser(__file__))))
sys.path.append(os.path.normpath(os.path.join(SCRIPT_DIR, PACKAGE_PARENT)))

from baidupcsapi import PCS

BASE_PATH = '/Baidu/Download/'


class RemoteDownload(object):

    def __init__(self,
                 baidu_username,
                 baidu_password,
                 rk_username,
                 rk_password,
                 rk_soft_id='90211',
                 rk_soft_key='bcf1f1cfb34449d7a133f99aa256b499'):
        self.baidu_username = baidu_username
        self.baidu_password = baidu_password

        self.captcha_params = {
            'username': rk_username,
            'password': md5(rk_password.encode('utf-8')).hexdigest(),
            'softid': rk_soft_id,
            'softkey': rk_soft_key,
            'typeid': 4040,  # 四位中文 验证码类型
            'timeout': 60,
        }

    def ruokuai_captcha_handler(s, params, image_url):
        """
            若快自动识别验证码, 文档见: http://wiki.ruokuai.com/
        """

        headers = {
            'Connection': 'Keep-Alive',
            'Expect': '100-continue',
            'User-Agent': 'ben',
        }
        image_data = requests.get(image_url).content
        files = {'image': ('check_code.png', image_data)}
        r = requests.post(
            'http://api.ruokuai.com/create.json',
            data=params,
            files=files,
            headers=headers
        )
        verify_code_dict = r.json()
        if verify_code_dict:
            if 'Error' in verify_code_dict.keys():
                print (verify_code_dict['Error'])
                return ''
            verify_code = verify_code_dict.get('Result', '')
        else:
            print ('rk failed ', verify_code_dict)
            return ''

        return verify_code

    def add_remote_download_task(self, link):
        """
            向百度网盘中添加离线下载链接
        """

        ruokuai_captcha_handler = functools.partial(
            self.ruokuai_captcha_handler,
            self.captcha_params
        )

        # 初始化pcs，这里设置了验证码处理函数和验证码处理参数
        pcs = PCS(
            self.baidu_username,
            self.baidu_password,
            ruokuai_captcha_handler,
            None,
        )

        # 获取下载路径中的文件，防止文件重复添加
        rsp = pcs.list_files(BASE_PATH)
        result = rsp.json()
        exist_list = []
        if result['errno'] == 0:
            exist_list = result['list']
        else:
            print(json.dumps(result))

        exist_names = [exist['server_filename'] for exist in exist_list]

        if link not in exist_names:
            # 网盘中不存在的才添加
            pcs.add_download_task(
                link,
                BASE_PATH
            )
        else:
            print(link + ' 已经存在于网盘中')

if __name__ == '__main__':
    """
        使用方法:
        1. 去ruokuai.com注册账号，并充值。(可以再注册一个开发者，用来自己实现打码软件，或者临时用我提供的soft_id & soft_key)
        2. 将RemoteDownload中的参数替换为你的百度账号密码，若快账号密码
        3. 回到包根目录，执行python3 examples/remote_download.py
    """
    download = RemoteDownload(
        'your_baidu_username',
        'your_baidu_password',
        'your_ruokuai_username',
        'your_ruokuai_password',
    )
    link = '''ed2k://|file|%E7%91%9E%E5%85%8B%E4%B8%8E%E8%8E%AB%E8%92%82.
    Rick%20and%20Morty.S01E05.MiniSD.854x480.%E4%B8%AD%E8%8B%B1%E5%8F%8C%E8%AF
    %AD-%E7%94%B5%E6%B3%A2%E5%AD%97%E5%B9%95%E7%BB%84.mp4|142618619|
    D65D44C81E315267E637DFB4B6D34632|h=4LONIB4A3I7HNYRXOFIN4BIMB2XCRYYN|/
    '''
    download.add_remote_download_task(link)
