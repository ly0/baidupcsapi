.. _API:

API列表
================================================


错误和异常
~~~~~~~~

.. exception:: baidupcsapi.LoginFailed
.. exception:: baidupcsapi.CancelledError

PCS类
~~~~~~~~

.. autoclass:: baidupcsapi.PCS
.. automethod:: baidupcsapi.PCS.__init__

连接设置
~~~~~~~~
.. automethod:: baidupcsapi.PCS.test_fastest_mirror
.. automethod:: baidupcsapi.PCS.set_fastest_baidu_server
.. automethod:: baidupcsapi.PCS.set_pcs_server


空间配额信息
~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.quota

上传单个文件
~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.upload

分片上传—文件分片及上传
~~~~~~~~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.upload_tmpfile

分片上传—合并分片文件
~~~~~~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.upload_superfile

下载单个文件
~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.download

创建目录
~~~~~~~~
.. automethod:: baidupcsapi.PCS.mkdir


获取目录下的文件列表
~~~~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.list_files

移动文件/目录
~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.move

拷贝文件/目录
~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.copy

删除文件/目录
~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.delete


高级功能
--------


获取流式文件列表
~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.list_streams

下载流式文件
~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.download

添加离线下载任务
~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.add_download_task

添加本地torrent
~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.add_local_bt_task

获取离线任务总数
~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.download_tasks_number

精确查询离线下载任务
~~~~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.query_download_tasks

查询离线下载任务列表
~~~~~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.list_download_tasks

取消离线下载任务
~~~~~~~~~~~~~~~~
.. automethod:: baidupcsapi.PCS.cancel_download_task


回收站
~~~~~~

查询回收站文件
++++++++++++++
.. automethod:: baidupcsapi.PCS.list_recycle_bin

还原文件或目录
++++++++++++++++++
.. automethod:: baidupcsapi.PCS.restore_recycle_bin

清空回收站
++++++++++
.. automethod:: baidupcsapi.PCS.clean_recycle_bin

