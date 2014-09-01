
百度网盘API文档
=======================================

本项目一些范例
------------
这些范例仅供参考使用, 代码糟糕, BUG未调.
全都是MIT协议的, 可以用各种姿势使用和娱乐.

基于百度网盘的FUSE

https://github.com/ly0/baidu-fuse/

百度网盘的web portal

https://github.com/ly0/web.baidupan/

写在前面
------------
有些接口由于百度的原因导致不可用, 请在本项目的github中提出.
很多接口没有给出返回的范例, 还是自己尝试一下返回的结果吧.

http://github.com/ly0/baidupcsapi

基于 mozillazg 的 baidu-pcs-python-sdk 改写而成

ref:https://github.com/mozillazg/baidu-pcs-python-sdk

安装
------------

.. code-block:: bash

    $ pip install baidupcsapi

链接
==================
   
* :ref:`API`
* :ref:`genindex`
* :ref:`search`

一个简单的例子
-----------

.. code-block:: python

    >>> from baidupcsapi import PCS
    >>> pcs = PCS('username','password')
    >>> print pcs.quota().content
    >>> print pcs.list_files('/').content
    
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
	                            ' ', progressbar.FileTransferSpeed()]
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




