#!/usr/bin/python2.6
#coding: utf-8
'''
POS机中间件，为支持python编译优化分离，written by xinl 2013/04/13
支持业务：
1：积分
2：撤消积分
3：查询当日某张积分卡的最近10笔交易（包括撤单）
4：更新积分比例
5：POS机初始化
6：按积分流水号查询积分详情
'''

from gevent.server import StreamServer
from multiprocessing import Process
import zmq.green as zmq
from gyconfig import *
from posp import cut
import struct, os, sys, time, memcache, re, gevent, uuid, logging, posp, security
from protocol_xgd import Pack_xgd
from protocol_xgd_posinit import Pack_xgd_pos
from protocol_security import Pack_security

################################################################################
sockd = {}							## 保存所有请求来源
workerPushMq = None

################################################################################
## DBHub使用
mac = None
dbs = {}

################################################################################
def init_mac():
	'''获得本机的MAC，更新全局变量mac
	'''
	global mac
	node = uuid.getnode()
	mac = uuid.UUID(int=node)
	mac = mac.hex[-12:]

def add_db_mq(addr, port, no = [x+1 for x in xrange(99)]):
	'''添加DBHub与管理公司资源号的对应关系，更新全局变量dbs
	addr - DBHub地址
	port - DBHub端口
	no - 该DBHub连接的数据库，保存的管理公司资源号列表
	'''
	c = zmq.Context()
	q = c.socket(zmq.DEALER)
	q.setsockopt(zmq.IDENTITY, '%s%d' % (mac, os.getpid()))
	q.connect('tcp://%s:%d' % (addr, port))

	global dbs
	for x in no:
		dbs[x] = q

def add_all_db():
	'''添加系统内所有DBHub，更新全局变量dbs
	'''
	for addr, nos in DBHubMap.items():
		add_db_mq(addr[0], addr[1], nos)

def buildhex(esn):
	s = hex(esn)[2:]
	s = '000000' + s
	return s[-6:]

################################################################################
class Request:
	'''公共请求类
	内部定义了每一个请求需要处理的逻辑，从而使得更改协议只需要更改协议定义类
	'''

	def __init__(self, sock, address, parserObj):
		'''初始化请求对象，通常是由gevent进程初始化
		@param sock - 提交本请求对象的socket对象，为返回应答准备
		@param address - socket对端地址
		@param parserObj - 业务协议对象
		'''
		self.status, self.key, self.parser, self.fd, self.addr = None, None, parserObj, sock.fileno(), address
		self.timers = posp.timerObj()

	def doGetKeys(self, mc):
		'''从安全线获得加密后的PIK和MAK
		'''
		data = None
		try:
			data = security.CRYPTOR.getKey(self.parser.EntNo, self.parser.PosNo, self.parser.oper, mc, self.parser.timer)
		except:
			posp.logger.exception('getKey Error')
			self.parser.data = struct.pack('!H', self.parser.reqNo)
		else:
			self.parser.data = struct.pack('!H20s20s', self.parser.reqNo, data[0], data[1])
		data = self.parser.packet('')
		return data

	def doPV(self, mc):
		'''积分
		'''
		data = None
		if self.status is None:
			#一次提交，向刷卡企业所在dber提交
			self.status = 'PV'
		elif self.status == 'PV Next':
			#二次提交，这次向积分卡所在dber提交
			pass
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doCancel(self, mc):
		'''撤单
		'''
		data = None
		if self.status is None:
			#一次提交，向积分卡所在dber提交
			self.status = 'Cancel'
		elif self.status == 'Cancel Next':
			#二次提交，这次向刷卡企业所在dber提交
			pass
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doUpdatePtScale(self, mc):
		'''更新积分比例
		'''
		data = None
		if self.status is None:
			self.status = 'Point Scale'
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doQueryToday(self, mc):
		'''查询当日积分卡最近10笔交易
		'''
		data = None
		if self.status is None:
			self.status = 'Query(s)'
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doQuerySingle(self, mc):
		'''查询单笔交易详情单
		'''
		data = None
		if self.status is None:
			self.status = 'Query'
		elif self.status == 'Query Next':
			pass
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doSignIn(self, mc):
		data = None
		if self.status is None:
			#先获取密钥，如果失败就没必要继续了
			ret = self.parser.getKey(mc)
			if ret is None:		#获取密钥失败
				self.ErrInfo, self.status = '内部错误', '9997'
				data = self.parser.packet(self.status, MEMCACHED=mc)
			else:
				self.parser.pinKey, self.parser.macKey = ret
				if self.parser.pinKey is None or self.parser.macKey is None:
					posp.logger.error('%s: get pin and mac keys failed' % self.parser.addr)
					return ''
				self.status = 'SignIn'
		else:
			#判定status，如果成功则产生batchNo
			if self.status == '0000':
				now = time.localtime(time.time())
				key = 'pos.generate.batchNo.counting.'+self.parser.EntNo+self.parser.PosNo
				mcret = mc.get(key)
				if mcret is None:
					batchno = 1
				elif isinstance(mcret, int):
					batchno = mcret;
				else:
					batchno = mcret[0]
				#产生了批次号认为签到完成，在memcache中记录签到时间
				mcret = [batchno, time.strftime('%Y%m%d', now)]
				mc.set(key, mcret)
				self.parser.batchNo = '%06d' % batchno
				posp.logger.debug('%s: generate batch no (%s) for %s:%s' % (self.parser.addr, self.parser.batchNo, self.parser.EntNo, self.parser.PosNo))
			else:
				self.parser.batchNo = ''
			data = self.parser.packet(self.status, MEMCACHED=mc)

		return data

	def doSignOff(self, mc):
		data = None
		if self.status is None:
			#设置签退状态
			self.status = 'SignOff'
		else:
			#更新为签退状态
			key = 'pos.generate.batchNo.counting.'+self.parser.EntNo+self.parser.PosNo
			mcret = mc.get(key)
			if mcret is None:
				mcret = [1, '']
			else:
				mcret[1] = ''
			#签退后把memcache中的签到时间清空
			mc.set(key, mcret)
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doBatchSettle(self, mc):
		data = None
		if self.status is None:
			self.status = 'BatchSettle'
		else:
			#在这里更新批次号
			key = 'pos.generate.batchNo.counting.'+self.parser.EntNo+self.parser.PosNo
			mcret = mc.get(key)
			if mcret is None:
				batchno = 0
			elif isinstance(mcret, int):
				batchno = mcret;
			else:
				batchno = mcret[0]
			batchno += 1
			if batchno > 999999:
				batchno = 1
			mcret[0] = batchno
			ret = mc.set(key, mcret)
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doPVPositive(self, mc):
		data = None
		if self.status is None:
			self.status = 'PV Positive'
		elif self.status == 'Positive Next':
			pass
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doCancelPositive(self, mc):
		data = None
		if self.status is None:
			self.status = 'Cancel Positive'
		elif self.status == 'Positive Next':
			pass
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doSynVars(self, mc):
		data = None
		if self.status is None:
			self.status = 'SynVars'
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doUpdVars(self, mc):
		data = None
		if self.status is None:
			self.status = 'UpdRates'
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def Reconciliate(self, mc):
		data = None
		if self.deals is None:
			self.deals = {}
		#	对账操作：
		self.parser.BalAcc = '1'#默认是平帐的
		for inp in self.parser.pcDeals:
			try:
				ent = self.deals[inp[0]]
			except:
				ent = None
			if ent is None:
				#如果该笔交易POS有而数据库没有,则设置对账结果为3
				ent = {}
				ent['PosSerial'], ent['CardNo'], ent['DealSum'], ent['DealRate'], ent['DealPtSum'], ent['DealPts'] = inp
				ent['Result'] = '3'
				self.parser.BalAcc = '2'
			else:
				#如果该笔交易双方都有，则记录双方数据，并设置标志对账结果,平帐则设置1,不平则设置2
				ent['PosSerial'], ent['CardNo'], ent['DealSum'], ent['DealRate'], ent['DealPtSum'], ent['DealPts'] = inp
				#判断平账：如果是积分需要判断交易金额，积分比例，积分金额和本次积分
				#撤单只需要比较本次积分
				def isbalance(inp, ent):
					try:
						if ent['db_CardNo'] != inp[1]:
							return False
						jyje = ent['DealSum']
						if int(jyje) > 0:
							if '%.2f'%ent['db_DealSum'] != '%.2f'%inp[2] or \
							   '%.2f'%ent['db_DealRate'] != '%.2f'%inp[3] or \
							   '%.2f'%ent['db_DealPtSum'] != '%.2f'%inp[4]:
								return False
						if ent['db_DealPts'] != inp[5]:
							return False
						return True
					except:
						return False
				if isbalance(inp, ent):
					ent['Result'] = '1'
				else:	#合并数据
					ent['Result'] = '2'
					self.parser.BalAcc = '2'
			#比较结果放回来
			self.deals[ent['PosSerial']] = ent
		#放回memcache
		if len(self.deals) > 0:		#只要有数据就应该放回memcache
			ret = mc.set(self.batchkey, self.deals)
			mc.set(self.batchkey+'.serialno', self.parser.serialno)
		#对账完成
		self.status = '0000'
		return self.parser.packet(self.status, MEMCACHED=mc)

	def doBatchUpdate(self, mc):
		data = None
		if self.status is None:
			#获取memcache数据
			self.batchkey = 'pos.'+self.parser.EntNo+self.parser.PosNo+self.parser.batchNo+'16'
			self.deals = mc.get(self.batchkey)
			self.parser.serialno = mc.get(self.batchkey+'.serialno')
			#如果为空则设置数据库获取 self.status='Batch Update'
			if self.deals is None:
				self.status = 'Batch Update'
			#如果memcache中有数据则开始进行对账：
			else:
				data = self.Reconciliate(mc)
		else:
			data = self.Reconciliate(mc)
		return data

	def doBatchDone(self, mc):
		data = None
		batchkey = 'pos.'+self.parser.EntNo+self.parser.PosNo+self.parser.batchNo+'16'
		if self.status is None:
			self.parser.batchMod = '207'
			#获取数据
			self.deals = mc.get(batchkey)
			#如果没有数据肯定是错误,那么在数据库中写入一条空数据
			if self.deals is None:
				#产生一条空数据
				self.deals = {}
				ent = {}
				ent['PosSerial'], ent['Result'] = '0', '5'
				self.deals['0'] = ent
				#return self.parser.packet(self.status, MEMCACHED=mc)
			else:
				#如果该笔交易POS没有而数据库(如果此时没有设置对账结果)有则设置对账结果为4
				for k in self.deals:
					ent = self.deals[k]
					if len(ent) <= 6:
						ent['Result'] = '4'
						self.parser.batchMod = '206'
					elif ent['Result'] != '1':
						self.parser.batchMod = '206'
					self.deals[k] = ent
			#转到数据库操作，提交deals到数据库
			self.status = 'Batch Done'
		else:
			#使用后在memcache中删除该批数据
			mc.delete(batchkey)
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doQueryEntInfo(self, mc):
		data = None
		if self.status is None:
			self.status = 'Ent Info'
		else:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doQueryPosOrders(self, mc):
		data = None
		if self.status is None:
			self.status = 'Orders'
		elif self.status == '0000':
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doOrderDetail(self, mc):
		data = None
		if self.status is None:
			self.status = 'Order Detail'
		elif self.status == '0000':
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doPosConfiged(self, mc):
		data = None
		if self.status is None:
			self.status = 'POS CFG'
		elif self.status == '0000':
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def doInit(self, mc):
		'''模拟POS机初始化，硬编码
		'''
		data = None
		if self.status is None:
			data = self.parser.packet(self.status, MEMCACHED=mc)
		return data

	def get_db_router(self, mqs):
		'''
		根据本地业务状态获得下一步要向哪个db发请求
		mqs - 所有DBHub的zmq channel字典
		'''
		def get_ent_db():
			'''获得刷卡企业DBHub地址
			'''
			try:
				key = int(self.parser.EntNo[0:2])
			except ValueError:
				posp.logger.error('%s: Invalid EntNo: %s' % (self.addr, self.parser.EntNo))
				return False
			return mqs.get(key, None)

		def get_card_db():
			'''获得持卡人DBHub地址
			'''
			try:
				key = int(self.parser.CardNo[0:2])
			except ValueError:
				posp.logger.error('%s: Invalid CardNo: %s', (self.addr, self.parser.CardNo))
				return False
			return mqs.get(key, None)

		if self.status == 'GetPosKey' or \
			self.status == 'PV' or \
			self.status == 'Cancel Next' or \
			self.status == 'Query' or \
			self.status == 'Orders' or \
			self.status == 'Order Detail' or \
			self.status == 'Ent Info' or self.status == 'POS CFG' or\
			self.status == 'SignIn' or self.status == 'SignOff' or \
			self.status == 'BatchSettle' or \
			self.status == 'Batch Update' or self.status == 'Batch Done' or \
			self.status == 'SynVars' or self.status == 'UpdRates':
			return get_ent_db()

		elif self.status == 'Verify' or \
			self.status == 'Query(s)' or \
			self.status == 'Query Next' or \
			self.status == 'PV Next' or \
			self.status == 'Cancel' or \
			self.status == 'PV Positive' or \
			self.status == 'Cancel Positive':
			return get_card_db()

	def doing(self, mqs, mc):
		'''业务处理方法，处理加解密、包解析、路由分发、打包等全部业务过程
		mqs - mqs - 所有DBHub的 zmq channel 字典
		mc - 内存数据库连接对象，当前为memcached
		return - str，表示上行到请求方，str为要返回的内容
				 zmq channel，表示请求下行到数据库
				 False，表示包结构错误，通知gevent直接断开连接
		'''
		if self.status == 'PacketError':
			return False

		if self.status is None:
			self.timers.count()
			x = self.parser.parse(PEER = self.addr, MEMCACHED = mc, TIMER = self.timers)
			self.timers.count('parse')

			self.Command, data = self.parser.typeName, None
			if not x:
				return False
			if isinstance(x, str):
				return x
			del self.parser.data

		self.timers.count()
		try:
			if self.Command == 1:	#积分
				data = self.doPV(mc)
			elif self.Command == 2:	#撤单
				data = self.doCancel(mc)
			elif self.Command == 3:	#查询当日交易
				data = self.doQueryToday(mc)
			elif self.Command == 5:	#POS机初始化
				data = self.doInit(mc)
			elif self.Command == 6:	#查询单笔积分流水
				data = self.doQuerySingle(mc)

			elif self.Command == 7:	#查询POS机订单列表
				data = self.doQueryPosOrders(mc)
			elif self.Command == 8:	#查询POS机订单详情
				data = self.doOrderDetail(mc)
			elif self.Command == 4:	#根据企业资源号查询企业详情
				data = self.doQueryEntInfo(mc)
			elif self.Command == 18: #设置POS机密钥烧入状态
				data = self.doPosConfiged(mc)

			elif self.Command == 9:  #签到
				data = self.doSignIn(mc)
			elif self.Command == 10: #签退
				data = self.doSignOff(mc)
			elif self.Command == 11:	#批结算
				data = self.doBatchSettle(mc)
			elif self.Command == 12:	#积分冲正
				data = self.doPVPositive(mc)
			elif self.Command == 13:	#撤单冲正
				data = self.doCancelPositive(mc)
			elif self.Command == 14:	#同步参数
				data = self.doSynVars(mc)
			elif self.Command == 15:	#上传参数
				data = self.doUpdVars(mc)
			elif self.Command == 16:	#批上传
				data = self.doBatchUpdate(mc)
			elif self.Command == 17:	#批上传结束
				data = self.doBatchDone(mc)

			elif self.Command == 19:	#密钥交换
				data = self.doGetKeys(mc)

			else:					#非法业务包
				posp.logger.error('%s Invalid Command[%d].' % (str(self.parser.addr), self.parser.Command))
				return False

		except:
			posp.logger.exception('doing error.')
			return False
		finally:
			self.timers.count('doing')

		if data is None:
			data = self.get_db_router(mqs)
		return data

################################################################################
def recv(sock, length):
	'''接收socket数据，直到接收了足够长度才返回
	length - 下一次要接收的数据长度
	return - None，发生异常
			 str，接收到的数据
	'''
	data = ''
	while 1:
		partial_data = ''
		try:
			partial_data = sock.recv(length - len(data))
		except:
			posp.logger.exception('gevent.recv')
			return None

		if len(partial_data) == 0:
			return None

		data += partial_data
		if len(data) == length:
			return data

def client_coroutine():
	'''数据发送协程，从 zmq channel 中不停地收取数据并发送到请求方
	'''
	while 1:
		obj = workerPushMq.recv_pyobj()
		sock = sockd.pop(obj.fd, None)
		if sock is None:
			posp.logger.error('%s: Invalid fd %d!' % (obj.addr, obj.fd))
			continue

		if ord(obj.data[0]) == 0x00 and ord(obj.data[1]) == 0xff:	#非法请求，断开连接
			sock.shutdown(2)

		else:	#返回应答包
			try:
				sock.sendall(obj.data)
			except:
				posp.logger.exception('Send failed')
			posp._hexdump(obj.data, 'Respond ' + str(obj.addr), logging.DEBUG)
			posp.logger.debug('Cmd:%d, %s' % (obj.Command, obj.timers))

		sock.close()

###############################################################################
def gevent_unit(sock, address):
	'''系统对外通讯接口，负责接收请求数据并分发给后面的业务进程
	sock - 连接请求方socket对象
	address - 连接请求方远程地址
	'''
#	posp.logger.debug('Accept Connection from %s' % str(address))

	data = False
	with gevent.Timeout(CLIENT_TIMEOUT, False):
		data = recv(sock, 2)
	if data is None:
		posp.logger.debug('%s Peer Closed!' % str(address))
		sock.close()
		return
	elif data == False:
		posp.logger.debug('%s Timeout!' % str(address))
		sock.shutdown(2)
		sock.close()
		return

	length = struct.unpack('!H', data)[0]

	if length <= 0 or length > 1024:
		posp.logger.error('Invalid packet length![%d]', length)
		sock.shutdown(2)
		sock.close()
		return

	encryptedBlock = False
	with gevent.Timeout(CLIENT_TIMEOUT, False):
		encryptedBlock = recv(sock, length)		#加密部分
	if encryptedBlock is None:
		posp.logger.debug('%s Peer Closed!' % str(address))
		sock.close()
		return
	elif encryptedBlock == False:
		posp.logger.debug('%s Timeout!' % str(address))
		sock.shutdown(2)
		sock.close()
		return

	posp._hexdump(encryptedBlock, 'Data ' + str(address), logging.DEBUG)

	parserObj = Parser.get(encryptedBlock[0:2], None)
	if parserObj is not None:
		parserObj = eval(parserObj)
	else:
		posp.logger.debug('Invalid Packet Type!')
		sock.shutdown(2)
		sock.close()
		return

	if not parserObj.addData(encryptedBlock):
		sock.shutdown(2)
		sock.close()
		return

	while 1:
		try:
			workerPushMq.send_pyobj(Request(sock, address, parserObj))
		except:
			posp.logger.exception('zmq feature')
			time.sleep(0.01)
		else:
			global sockd
			sockd[sock.fileno()] = sock
			break

#	posp.logger.debug('gevent -> worker')

################################################################################
def business_process():
	'''业务处理进程
	TODO:Nosql持久化，支持跨数据库业务中间状态缓存
	'''
	ff = open('pid.pid', 'a')
	ff.write('%d\n' % os.getpid())
	ff.close()

	posp.logger = logging.getLogger('W(%d)' % os.getpid())
	if GYDEBUG == False:
		posp._hexdump = posp.hexdumpNone
#	posp.logger.info('Worker started.')

	c = zmq.Context()
	getMq = c.socket(zmq.DEALER)
	getMq.connect(zmq_gevent2worker)

	add_all_db()

	mc = memcache.Client(cache_addr)

	poller = zmq.Poller()
	poller.register(getMq, zmq.POLLIN)
	for mq in dbs.values():
		poller.register(mq, zmq.POLLIN)

	while 1:
		socks = dict(poller.poll())

		for x in socks.keys():
			obj = x.recv_pyobj()
#			if id(x) == id(getMq):
#				posp.logger.debug('worker get request')
#			else:
#				posp.logger.debug('worker get response')

			ret = obj.doing(dbs, mc)
			if ret is None:		#没有解析出下一个dbproxy
				try:
					if hasattr(obj.parser, 'CardNo'):
						posp.logger.error('%s: Parse dbproxy Error! Status[%s], EntNo[%s], CardNo[%s]' % (obj.parser.addr, obj.status, obj.parser.EntNo, obj.parser.CardNo))
					else:
						posp.logger.error('%s: Parse dbproxy Error! Status[%s], EntNo[%s], CardNo[None]' % (obj.parser.addr, obj.status, obj.parser.EntNo))
					obj.data = obj.parser.onFatalError()
				except AttributeError:
					posp.logger.exception('Error')
					obj.data = '\x00\xff'

#				posp.logger.debug('worker -> gevent: %d' % (obj.parser.Command, ))
				del obj.parser
				getMq.send_pyobj(obj)
			elif isinstance(ret, str):
				posp.logger.debug('%s Command = %d returned.' % (obj.addr, obj.parser.Command))
				obj.data = obj.parser.onAnswer(ret)
				posp.logger.debug('worker -> gevent: %d' % (obj.parser.Command, ))
				del obj.parser
				getMq.send_pyobj(obj)
			elif ret == False:
				posp.logger.error('%s: Invalid packet, close peer.' % (obj.addr, ))
				obj.data = obj.parser.onFatalError()
				posp.logger.debug('worker -> gevent: %d' % (obj.parser.Command, ))
				del obj.parser
				getMq.send_pyobj(obj)
			else:
#				posp.logger.debug('worker -> dbhub: %d' % (obj.parser.Command, ))
				ret.send_pyobj(obj)

###############################################################################
def gevent_process():
	'''启动对外访问进程和工作进程
	'''
	init_mac()

	for i in xrange(PROCESS_COUNT - 1):
	    Process(target=business_process, args=tuple()).start()

	global workerPushMq
	c = zmq.Context()
	workerPushMq = c.socket(zmq.DEALER)
	workerPushMq.bind(zmq_gevent2worker)

	ff = open('pid.pid', 'a')
	ff.write('%d\n' % os.getpid())
	ff.close()

	posp.logger = logging.getLogger('G(%d)' % os.getpid())
	if GYDEBUG == False:
		posp._hexdump = posp.hexdumpNone

	gevent.spawn(client_coroutine)

	server = StreamServer(LISTEN_ADDR, gevent_unit, backlog=100000)
	server.pre_start()
	server.start_accepting()
	server._stopped_event.wait()

	zmq.close()
	zmq.term()
