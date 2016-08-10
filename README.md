百度网盘API
====================================

讨论
======
[Google Group](https://groups.google.com/forum/#!forum/baidupcsapi)

贡献者(字典序)
======
* [a1exwang](https://github.com/a1exwang)
* [capric8416](https://github.com/a1exwang)
* [jonans](https://github.com/jonans)
* [ly0](https://github.com/ly0)
* [morefreeze](https://github.com/morefreeze)

项目名称解释
-----------
后来我才搞清楚pcs并不是指百度网盘，想过改成baidupanapi但是由于历史原因就算了。

文档
-----------
http://baidupcsapi.readthedocs.org/

TODOS
------
* [ ] 获取分享链接中文件列表接口
* [ ] 保存分享到用户网盘接口

随时更新处
-----------

* 再也不会看到 *wenxintishi.avi* 了!
* 百度网盘登录现在需要RSA加密后传输, 详情请参考 *api.py* 中的 *PCS._get_pubkey* 和 *PCS._login* 函数
* 新加入 *PCS.download_url* 方法, 可以直接获得可用下载链接 (支持批量下载, 参数为 *str* 或者 *str list*)
* 记住验证码的处理函数在初始化 *PCS* 类时通过 *captcha_func* 参数指定, 其中第一个参数会给予 JPEG 数据, handler 处理完后需要返回一个可行的验证码.


正文
======================

~~百度网盘现在不开放PCS API，所以目前只能用百度自己的API~~
应该是可以了,参考 (https://github.com/mozillazg/baidu-pcs-python-sdk/wiki/%E5%A6%82%E4%BD%95%E8%8E%B7%E5%8F%96-Access-Token-%E5%92%8C-Refresh-Token%EF%BC%9F)

一个基于此api的 fuse（测试环境ubuntu12.04）
http://github.com/ly0/baidu-fuse

web版百度网盘(可以用来开放资源,测试环境ubuntu14.04)
https://github.com/ly0/web.baidupan

* 文档 http://ly0.github.io/baidupcsapi
* Free software: MIT license
* PyPI: https://pypi.python.org/pypi/baidupcsapi
* Python version: 2.7
* require: requests>=2.0.0, requests_toolbelt>=0.1.2

* 删掉了一些原作者在pan.baidu.com上没有的api，修改了大部分api和相关的程序部分，为了区分原作者的程序,在pypi上发布为baidupcsapi


Installation
------------

To install baidupcsapi, simply:

```shell
$ pip install baidupcsapi
```

一些简单的例子
-----------
```python
>>> from baidupcsapi import PCS
>>> pcs = PCS('username','password')
>>> print pcs.quota().content
>>> print pcs.list_files('/').content
```

断点续传
-----------

下载
-------


```python
>>> headers = {'Range': 'bytes=0-99'}
>>> pcs = PCS('username','password')
>>> pcs.download('/test_sdk/test.txt', headers=headers)
```

上传
-------

上传文件的进度条实现范例
------

回调函数参数要求 有size和progress两个参数名，
		size：文件总字节数
		progress：当前传输完成字节数
		
```python
import progressbar
from baidupcsapi import PCS
class ProgressBar():
    def __init__(self):
        self.first_call = True
    def __call__(self, *args, **kwargs):
        if self.first_call:
            self.widgets = [progressbar.Percentage(), ' ', progressbar.Bar(marker=progressbar.RotatingMarker('>')),
                            ' ', progressbar.ETA()]
            self.pbar = progressbar.ProgressBar(widgets=self.widgets, maxval=kwargs['size']).start()
            self.first_call = False

        if kwargs['size'] <= kwargs['progress']:
            self.pbar.finish()
        else:
            self.pbar.update(kwargs['progress'])


pcs = PCS('username','password')
test_file = open('bigfile.pdf','rb').read()
ret = pcs.upload('/',test_file,'bigfile.pdf',callback=ProgressBar())
```

上传大文件
------

将大文件切成一个个块，分批上传
注意upload系列的函数都可以指定callback参数

```python
#coding: utf-8
import os,json,sys,tempfile
from baidupcsapi import PCS

pcs = PCS('username','password')
chinksize = 1024*1024*16
fid = 1
md5list = []
tmpdir = tempfile.mkdtemp('bdpcs')
with open(sys.argv[1],'rb') as infile:
    while 1:
        data = infile.read(chinksize)
        if len(data) == 0: break
        smallfile = os.path.join(tmpdir, 'tmp%d' %fid)
        with open(smallfile, 'wb') as f:
            f.write(data)
        print('chunk%d size %d' %(fid, len(data)))
        fid += 1
        print('start uploading...')
        ret = pcs.upload_tmpfile(open(smallfile, 'rb'))
        md5list.append(json.loads(ret.content)['md5'])
        print('md5: %s' %(md5list[-1]))
        os.remove(smallfile)

os.rmdir(tmpdir)
ret = pcs.upload_superfile('/'+os.path.basename(sys.argv[1]), md5list)
print ret.content
```

`python upload.py huge_file`

