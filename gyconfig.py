#!/usr/bin/python2.6
#coding: utf-8

#POS机中间件配置文件，written by xinl 2013/04/13

################################# 可修改配置 ####################################
## gevent
LISTEN_ADDR = ('', 11717)			## 对外服务端口
CLIENT_TIMEOUT = 20					## 对外服务socket闲置时间（秒），超过这个时间没有收到数据将关闭该socket
CRYPTOSVR = [('192.168.1.116', 18087)]	## 安全线连接地址，可以配置多个密钥服务器

## 管理公司资源号 与 DBHub的地址 的对应关系，格式：(IP,端口):[管理公司资源号(2位数字),...]
DBHubMap = {('127.0.0.1', 11718) : [x+1 for x in xrange(99)]}

## oracle
DBUSER = 'test0718'                 ## 本机连接数据库的用户名
DBPWD = '111111'                    ## 本机连接数据库的密码
DSN = '192.168.1.200:1521/orcl'     ## 数据库连接字符串，不能使用localhost
DB_CONN = 16						## 每个dber建立多少条到oracle的连接
DB_TIMEOUT = 10						## 数据库查询超时时间

## 公共配置
PROCESS_COUNT = 8					## 本机CPU个数
cache_addr = ['192.168.1.116:11211']## memcached地址
GYDEBUG = True						## DEBUG开关，调试时设为True，正式使用时设为False
LOGMAXIUM = 10						## 单个日志文件大小，单位兆

## 业务配置
limit_ratio = (1, 3000)				## 积分比例限制
ERROR_PARSE = 3						## 连续收到错误包次数后要求重新签到
TestWait = 0.02						## 测试时就地返回使用的延时，单位秒

## zmq channel，不要轻易改变
zmq_gevent2worker = 'ipc://gevent.worker.dev'	## gevent <-> worker
zmq_dbhub2worker = 'tcp://*:11718'			## Worker <-> DBHub，本机DBHub服务channel，与上面的DBHubMap形成对应关系
zmq_dbhub2proxy = 'ipc://hub.dbproxy.dev'		## DBHub <-> DBProxy

## 业务解析器配置
Parser = {
	'\x60\x85' : 'Pack_xgd()',
	'\x60\xff' : 'Pack_xgd_pos()',
	'\x60\x60' : 'Pack_security()'
}
