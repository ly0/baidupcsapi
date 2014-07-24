百度网盘API
====================================

随时更新处
-----------

* 百度网盘登录现在需要RSA加密后传输, 详情请参考 *api.py* 中的 *PCS._get_pubkey* 和 *PCS._login* 函数
* 新加入 PCS.download_url 方法, 可以直接获得可用下载链接 (支持批量下载, 参数为 *str* 或者 *str list*)

百度网盘现在不开放PCS API，所以目前只能用百度自己的API

一个基于此api的 fuse（测试环境ubuntu12.04）
http://github.com/ly0/baidu-fuse

* 文档 http://baidupcsapi.rtfd.org
* Free software: MIT license
* PyPI: https://pypi.python.org/pypi/baidupcsapi
* Python version: 2.7
* require: requests>=2.0.0, requests_toolbelt>=0.1.2

* 删掉了一些原作者在pan.baidu.com上没有的api，修改了大部分api和相关的程序部分，为了区分原作者的程序,在pypi上发布为baidupcsapi


Installation
------------

To install baidupcsapi, simply:

.. code-block:: bash

    $ pip install baidupcsapi


一些简单的例子
-----------

.. code-block:: python

    >>> from baidupcsapi import PCS
    >>> pcs = PCS('username','password')
    >>> print pcs.quota().content
    >>> print pcs.list_files('/').content

断点续传
-----------

下载
-------

.. code-block:: python

          >>> headers = {'Range': 'bytes=0-99'}
          >>> pcs = PCS('username','password')
          >>> pcs.download('/test_sdk/test.txt', headers=headers)
上传
-------

有时间写个demo，大概是
将文件分块，计算每一块的MD5
precreate 对于服务器上的某个文件需要上传的块
upload_tmpfile 上传临时文件（块）
upload_superfile 合并块（在precreate返回所需块为空时调用本函数可合并文件）
注意，百度服务器上文件是分块保存的，块不会消失

  
上传文件的进度条实现范例
------

回调函数参数要求 有size和progress两个参数名，
		size：文件总字节数
		progress：当前传输完成字节数
		
.. code-block:: python

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

合并文件
------

可以用两个纯文本文档合并，这样产生的新文档是两个文本文档的文字合并
注意upload系列的函数都可以指定callback参数

.. code-block:: python
	
	pcs = PCS('username','password')
	print 'chunk1'
	ret = pcs.upload_tmpfile(open('1.txt','rb'))
	md51 = json.loads(ret.content)['md5']
	print 'chunk2'
	ret = pcs.upload_tmpfile(open('2.txt','rb'))
	md52 = json.loads(ret.content)['md5']
	print 'merge'
	ret = pcs.upload_superfile('/3.txt',[md51,md52])
	print ret.content
	# 查看3.txt
	
在根目录下就会有3.txt

