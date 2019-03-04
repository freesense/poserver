#!/usr/bin/python2.6
#coding: utf-8

'''基础库支持
'''

import logging, struct, heapq, time, threading
from datetime import datetime, timedelta

logger = None						## 日志

########################################################################
def cut(s):
	'''
	处理字符串，截掉尾部\0后面所有内容
	s - 要处理的字符串
	return - 处理好的字符串
	'''
	return s.split('\0', 1)[0]

def hexdumpNone(data, text = 'Hexdump', lv = logging.DEBUG):
	'''16进制输出的dummy函数
	不做任何事情
	'''
	pass

def hexdump(data, text = 'Hexdump', lv = logging.DEBUG):
	'''16进制输出，向logging模块输出
	data - 要输出的数据
	text - 输出标题
	lv - 输出级别
	'''
	global logger
	if data is None:
		logger.log(lv, '%s, None' % text)
		return

	outs = []
	outs.append('%s, length = %d' % (text, len(data)))
	l, r, x = [], [], 0
	for c in data:
		l.append('%02x ' % ord(c))
		if ord(c) >= 32 and ord(c) <= 126:
			r.append(c)
		else:
			r.append('.')
		x += 1
		if x == 16:
			outs.append('%-48s%-16s' % (''.join(l), ''.join(r)))
			l, r, x = [], [], 0
	if len(r) > 0:
		outs.append('%-48s%-16s' % (''.join(l), ''.join(r)))
	outs = '\n'.join(outs)
	logger.log(lv, outs)

_hexdump = hexdump

########################################################################
class timerObj:
	def __init__(self):
		if __debug__:
			self.t, self.base = {}, datetime.now()

	def __str__(self):
		if __debug__:
			s, d = [], 'db: [%s, %s, %s]' % (str(self.t.get('predb', '0:00:00.00000'))[5:], str(self.t.get('db', '0:00:00.00000'))[5:], str(self.t.get('postdb', '0:00:00.00000'))[5:])
			for k, v in self.t.items():
				if k not in ['predb', 'db', 'postdb']:
					s.append('%s: %s, ' % (k, str(v)[5:]))
			s.append(d)
			return ''.join(s)
		else:
			return ''

	def count(self, name = None, base = None):
		'''计时器
		@param name - 计时器名字
					  None：重置计时器
					  字符串：本次计时将累加入该计时器中
		'''
		if __debug__:
			_now = datetime.now()
			if base is None:
				base = self.base
			delta, self.base = _now - base, _now

			if name is not None:
				delta += self.t.get(name, timedelta())
				self.t[name] = delta

def timerHelper(obj, name):
	'''计时器装饰
	@param obj - 计时时间，函数执行时间将记录到到obj对象的t字典中
				 name不存在则添加name，name存在则增加name
	'''
	def _timer(func):
		def __timer(*args, **kwargs):
			if __debug__:
				t = Timing()

			ret = func(*args, **kwargs)

			if __debug__:
				__elapse = t.count()
				tm = obj.t.get(name, None)
				if tm is None:
					obj.t[name] = __elapse
				else:
					tm += __elapse

			return ret
		return __timer
	return _timer

########################################################################
class PacketBase:
	'''多协议支持基类，所有通讯协议由此继承，遵循统一的业务流程
	数据格式=!H+Body，H为后面Body的长度
	Body=!H+Data，H为协议标志符，例如\x60\x85为新国都8583协议，\x60\xff为新国都灌录密钥协议
	'''

	def addData(self, data):
		'''收到协议包体数据时，调用本方法将包体数据传递给协议对象处理
		@param data - 包体数据
		@return True - OK
				False - 数据错误，需要断开连接
		'''
		pass

	def parse(self, **args):
		'''
		子类在本方法里解析接收到的数据
		args['PMK'] - POS机主密钥
		args['PEER'] - 通讯对端的地址、端口
		return - True，解析成功
				 False，解析失败，gevent将拆掉连接
		'''
		return False

	def packet(self, status, **args):
		'''
		子类在本方法里打包要返回的应答，与下面onAnswer方法的区别在于本方法首先调用，并且要返回打包数据，应用根据返回的数据决定下一步动作
		status - 业务前处理状态
		args - 暂不处理
		return - None，交给DBHub处理本包
				 str，返回给请求发起方
		'''
		pass

	@property
	def typeName(self):
		'''
		获得本次业务类型，业务类型定义在本文件头部
		return - 业务类型，非标准业务类型将导致gevent断开与请求方的连接
		'''
		return None

	def onFatalError(self):
		'''
		致命错误，通知gevent断开与请求方的连接
		'''
		return struct.pack('!2H', 0xff, 0xff)

	def onAnswer(self, data):
		'''
		最终打包方法
		data - packet方法中返回的数据
		return - 应答完整包
		'''
		pass

########################################################################
## 定时器

class _timer:
	def __init__(self, seconds, cb, param):
		self.bErase, self.trigger, self.cb, self.param = False, time.time() + seconds, cb, param

	def __eq__(self, other):
		return self.trigger == other.trigger

	def __gt__(self, other):
		return self.trigger > other.trigger

	def __lt__(self, other):
		return self.trigger < other.trigger

heap_lock, waitEvent, timer_heap = None, None, []

def time_thread():
	'''定时器调度线程
	'''
	obj, timeout = None, None
	while 1:
		try:
			waitEvent.wait(timeout)
			if waitEvent.is_set():
				waitEvent.clear()
			else:				## 超时，表示需要回调并删除该定时器
				obj.bErase = True
				obj.cb(obj.param)

			## 取下一个定时器
			with heap_lock:
				while 1:
					obj = heapq.nsmallest(1, timer_heap)
					if len(obj) == 0:
						obj, timeout = None, None
						break
					if obj[0].bErase:
						heapq.heappop(timer_heap)
					else:
						obj = obj[0]
						timeout = obj.trigger - time.time()
						break
		except:
			logger.exception('timer thread')

def time_reactor():
	'''启动定时器调度线程，初始化定时器环境
	'''
	global waitEvent, heap_lock
	waitEvent = threading.Event()
	heap_lock = threading.RLock()
	waitEvent.clear()

	x = threading.Thread(target = time_thread)
	x.start()
	return x

def add_timer(seconds, cb, *args):
	'''添加定时器
	'''
	t = _timer(seconds, cb, args)

	with heap_lock:
		heapq.heappush(timer_heap, t)

	waitEvent.set()
	return t

def del_timer(timer):
	'''删除定时器
	'''
	timer.bErase = True
	waitEvent.set()

def test_timer():
	def __cb(x):
		print time.strftime('%Y-%m-%d %H:%M:%S'), 'timer callback', time.time() - x[0]

	t = time_reactor()

	print time.strftime('%Y-%m-%d %H:%M:%S'), 'set 10 and 3'
	x = add_timer(10, __cb, time.time())
	add_timer(3, __cb, time.time())
	time.sleep(4)
	print time.strftime('%Y-%m-%d %H:%M:%S'), 'del 10'
	del_timer(x)
	print time.strftime('%Y-%m-%d %H:%M:%S'), 'set 2 and 5'
	add_timer(2, __cb, time.time())
	add_timer(5, __cb, time.time())
	return t

if __name__ == "__main__":
	x = test_timer()
	x.join()
