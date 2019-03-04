#!/usr/bin/python2.6
#coding: utf-8

'''新国都8583业务
'''

import struct, time, posp, gyconfig, hashlib, logging, gevent, security
from datetime import datetime
from gyconfig import *
from Py8583 import *

###############################################################################
class Pack_xgd(posp.PacketBase):
	'''新国都8583协议
	'''
	pinKey, macKey, CardNo, pwd, EntNo, serialno, Command, needSignAgain, XGDTPDU, XGDTPDU_SIGN = None, None, None, None, None, None, 0, True, '\x60\x85\x83\x85\x83\x64\x31\x00\x60\x00\x01', '\x60\x85\x83\x85\x83\x64\x31\x03\x60\x00\x01'
	cryptor = security.CRYPTOR

	def getKey(self, mc):
		'''获得加密后的Pin Key和Mac Key
		@return - 使用PMK加密后的PIK和MAK
		'''
		try:
			return self.cryptor.getKey(self.EntNo, self.PosNo, self.oper, mc, self.timer)
		except:
			self.serialno = '0'
			posp.logger.exception('getKey Error')
			return None

	def getMac(self, data, mc):
		'''获得MAC值
		@param data - 需要做MAC的数据
		@return - 8个字节的MAC码
		'''
		try:
			return self.cryptor.getMac(self.EntNo, self.PosNo, self.oper, data, mc, self.timer)
		except:
			self.serialno = '0'
			posp.logger.exception('getMac Error')
			return None

	def encrypt(self, data, mc):
		'''加密
		@param data - 明文数据
		@return - 密文数据
		'''
		try:
			return self.cryptor.encrypt(self.EntNo, self.PosNo, self.oper, data, mc, self.timer)
		except:
			self.serialno = '0'
			posp.logger.exception('encrypt Error')
			return None

	def decrypt(self, data, mc):
		'''解密
		@param data - 密文数据
		@return - 明文数据
		'''
		try:
			return self.cryptor.decrypt(self.EntNo, self.PosNo, self.oper, data, mc, self.timer)
		except:
			self.serialno = '0'
			posp.logger.exception('decrypt Error')
			return None

	def bind_req(self, data, pin, mc):
		'''合并解密和产生mac两个功能
		@param data - 需要做mac的数据
		@param pin - 需要解密的持卡人密码
		@return (mac数据， 解密数据)
		'''
		try:
			return self.cryptor.bind_req(self.EntNo, self.PosNo, self.oper, data, mc, self.timer)
		except:
			self.serialno = '0'
			posp.logger.exception('bind_req Error')
			return None

	##############################################################################
	def addData(self, data):
		head, self.data = data[0:11], data[11:]
		if head != self.XGDTPDU:
			posp.hexdump(head, 'Invalid Packet Head!', logging.ERROR)
			return False
		return True

	def parseBasic(self):
		'''解析企业资源号、POS机编号、POS流水号
		结果存放在self.EntNo, self.PosNo, self.PosSerial里面，其数据格式已经标准化
		POS流水号是非必须的，未取到不作为错误数据包
		'''
		try:
			self.PosSerial = self.parseObj.getBit(11)
		except:
			self.PosSerial = None
		try:
			self.EntNo, self.PosNo = self.parseObj.getBit(42)[-11:], self.parseObj.getBit(41)[-2:]
		except:
			posp.logger.exception('parseBasic error!')
			return False
		else:
			if not self.EntNo.isdigit():
				return False
			if not self.PosNo.isdigit():
				return False
			return True

	def checkCard(self, cardno, sz):
		'''卡号检查：
		必须是数字
		二磁道为15位(去掉国家码后)
		2域数据至少11位
		'''
		i = 0;
		if not cardno.isdigit():
			return False
		if i != sz:
			return False
		return True

	def parseCard(self, mc):
		'''解析持卡人卡号、持卡人密码
		解析结果存放在self.CardNo, self.pwd中，其数据格式已经标准化
		@return True - 解析成功，但是self.CardNo, self.pwd可能为None
				False - 解析失败，包结构错误，需要断开连接
		'''
		clen = 0
		try:
			bit22 = self.parseObj.getBit(22)[0:3]
		except:	#不存在22域
			self.CardNo, self.pwd = None, None
		else:
			try:
				if bit22[0:2] == '01':
					self.CardNo = self.parseObj.getBit(2)[-11:]
					clen = 11
				elif bit22[0:2] == '02':
					self.CardNo = self.parseObj.getBit(35)
					try:
						cno,cinfo = self.CardNo.split('D')	#截取d之前的部分
						self.CardNo = cno + cinfo[-4:]
					except:
						self.CardNo = self.CardNo[0:11] + self.CardNo[-4:]
					clen = 15
				else:
					posp.logger.error('Invalid bit22')
					return False

				if bit22[2:] == '1':
					bit52 = self.parseObj.getBit(52)
					self.pwd = self.decrypt(bit52[0:8], mc)
					if self.pwd is None:
						return False
					self.pwd = hashlib.md5(self.pwd).hexdigest()
				else:
					self.pwd = ''
			except:
				posp.logger.exception('parseCard error!')
				return False
			#卡号检查，长度和字符
			if self.checkCard(self.CardNo, clen):
				return False
			return True
		return False

	def verify(self, mc):
		'''MAC校验
		如果连续3次校验错误则要求pos重新签到
		'''
		key = 'pos.maccheck.error.count.'+self.EntNo+self.PosNo
		try:
			mymac = self.parseObj.getBit(64)
		except:
			if self.mt in (400, 900, 920):	#必须作MAC校验的
				return False;
			return True
		else:
			mac = self.getMac(self.data[0:-8], mc)
			if mac is None:
				return False
			elif mac[0:8] != mymac:
				#输出
				posp.hexdump(self.data, 'Verify failed: %s' % mac, logging.ERROR)

				#设置错误信息
				try:
					errcount = mc.get(key)
				except:
					mc.set(key, 1)
					return False
				else:
					if errcount is None:
						errcount = 1
					else:
						errcount += 1
					if errcount >= 3:
						mc.delete (key)
						self.needSignAgain = True
						return ''
					else:
						mc.set(key, errcount)
				return False
			else:
				mc.delete (key)
				return True

	def hasSigned(self, mc):
		return True
		'''判断该pos是否签到
		如果没有签到则应当让其重新签到
		'''
		if self.mt == 800:	#如果是签到业务，则直接继续进行
			return True
		key = 'pos.generate.batchNo.counting.'+self.EntNo+self.PosNo
		mcret = mc.get(key)
		today = time.strftime('%Y%m%d', time.localtime(time.time()))
		if mcret is None or not isinstance(mcret, list) or mcret[1] != today:
			self.needSignAgain = True
			posp.logger.error('%s: did not signed in yet %s:%s' % (self.addr, self.EntNo, self.PosNo))
			return ''
		else:
			return True

	def getBit(self, bit):
		ret = None
		try:
			ret = self.parseObj.getBit(bit)
		except:
			posp.logger.error('Bit %d did not set' % bit)
		return ret

#	@posp.timerHelper(self.tmdes)
	def parse(self, **args):
		self.oper, self.addr, self.ErrInfo, mc, self.timer = '', str(args.get('PEER', 'Unknown')), '', args.get('MEMCACHED', None), args.get('TIMER', None)
		if mc is None:
			posp.logger.critical('memcached server unavailable!')
			return False

		try:
			if __debug__: t = datetime.now()
			self.parseObj = Py8583()
			self.parseObj.parse(self.data)
		except:
			posp.logger.exception('Parse Request')
			posp.hexdump(self.data, 'Parse Request', logging.ERROR)
			return False

		if __debug__: self.timer.count('8583', t)

		#获取消息类型
		self.mt = self.parseObj.mti
		#获取基础信息
		if not self.parseBasic():
			return False
		sgned = self.hasSigned(mc)
		#如果还没有签到则要求对方进行签到
		if not sgned:
			retobj = Py8583()
			retobj.mti = self.mt
			retobj.setBit(11, self.PosSerial)
			now = time.localtime(time.time())
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(32, self.EntNo[0:2]+'000000')
			retobj.setBit(39, '90')
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.setBit(62, u'请签到'.encode('gbk'))

			retobj.setBit(64, '00000000')
			retstr = retobj.getRawIso()
			mac = self.getMac(retstr, mc)
			if mac is None:
				return False
			retobj.setBit(64, mac[0:8])
			return retobj.getRawIso()

		if self.mt == 800:		# 签到
			self.Command = 9
			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = oper[-3:]
			except:
				posp.hexdump(self.data, "Unpack Sign In", logging.ERROR)
				self.needSignAgain = True
				return ''
			if self.EntNo is None or self.PosNo is None:
				posp.logger.error('%s: Get Enterprise No and POS No failed' % self.addr)
				self.needSignAgain = True
				return ''
			#判断60域
			try:
				offset, _ = self.parseObj.getBitNext(60, 0, ('N', 2))
				offset, _ = self.parseObj.getBitNext(60, offset, ('N', 6))
				offset, d3 = self.parseObj.getBitNext(60, offset, ('N', 3))
			except:
				self.needSignAgain = True
				return ''
			else:
				if d3 != '003':	#如果60域没有设置或者60.3域不为003(双倍长密钥算法),则返回错误
					self.needSignAgain = True
					return ''

		elif self.mt == 820:	# 签退
			self.Command = 10

			if self.PosSerial is None:
				self.PosSerial = ''
			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = oper[-3:]
			except:
				self.oper = ''

			offset, _ = self.parseObj.getBitNext(60, 0, ('N', 2))
			offset, self.fld60_2 = self.parseObj.getBitNext(60, offset, ('N', 6))

		elif self.mt == 900:	#积分/积分撤单
			#判断是积分还是撤单
			try:
				self.op = self.parseObj.getBit(3)[0:2]
				if self.op == '21': #积分
					self.Command = 1
				else:
					self.Command = 2
			except:
				posp.logger.error('Unpack error')
				return False

			ret = self.verify(mc)
			if not ret:	#校验MAC
				return False
			if isinstance(ret, str):
				return ret

			if not self.parseCard(mc):
				return False

			#获取操作员
			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = oper[1:4]
			except:
				posp.logger.error('Unpack error')
				return False

			self.fld25 = self.parseObj.getBit(25)

			if self.op == '21': #积分
				try:
					je = self.parseObj.getBit(4)
					self.je = int(je)
					pos, jfbl = self.parseObj.getBitNext(48, 0, ('N', 4))
					pos, jf = self.parseObj.getBitNext(48, pos, ('N', 12))
					self.jfbl = int(jfbl)
					self.jf = int(jf)
					currency = self.parseObj.getBit(49)			#货币
					self.currency = int(currency)
					pos, self.TransType = self.parseObj.getBitNext(60, 0, ('N', 2))
					pos, self.orgBatch = self.parseObj.getBitNext(60, pos, ('N', 6))
					self.orgSerial = self.PosSerial
				except:
					posp.logger.error('Unpack PV error')
					return False
				else:
					pass
			elif self.op == '20': #积分撤单
				#原单信息
				try:
					self.waitcancelOrderNo = self.parseObj.getBit(37)		#待撤单号
					offset, self.f601 = self.parseObj.getBitNext(60, 0, ('N', 2))
					offset, self.batch = self.parseObj.getBitNext(60, offset, ('N', 6))
				except:
					posp.logger.error('Unpack Cancel error')
					return False
			else:
				posp.logger.error('Unkonw operate %s' % self.op)
				return False

		elif self.mt == 920:		#查询卡当日记录，卡单条记录
			try:
				self.op = self.parseObj.getBit(3)[0:2]
			except:
				posp.logger.exception('%s Query' % self.addr)
				return False

			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = oper[-3:]
			except:
				self.oper = ''

			if self.op == '70':		#当日记录
				self.Command = 3
				ret = self.verify(mc)
				if not ret:	#校验MAC
					return False
				if isinstance(ret, str):
					return ret

				if not self.parseCard(mc):
					return False

				self.fld25 = self.parseObj.getBit(25)
				offset, self.transType = self.parseObj.getBitNext(60, 0, ('N', 2))
				offset, self.batchNo = self.parseObj.getBitNext(60, offset, ('N', 6))

			elif self.op == '71':		#单条数据
				self.Command = 6
				ret = self.verify(mc)
				if not ret:	#校验MAC
					return False
				if isinstance(ret, str):
					return ret

				try:
					self.orgSerial = self.parseObj.getBit(37)
					offset, self.transType = self.parseObj.getBitNext(60, 0, ('N', 2))
					offset, self.batchNo = self.parseObj.getBitNext(60, offset, ('N', 6))
				except:
					posp.logger.exception('%s query serial or batch is not set' % self.addr)

		elif self.mt == 400:		#积分冲正/积分撤单冲正
			#判断是积分还是撤单
			try:
				self.op = self.parseObj.getBit(3)[0:2]
			except:
				posp.logger.error('%s bit 3 is not set' % self.addr)
				return False

			if self.op == '21': #积分冲正
				self.Command = 12
			elif self.op == '20': #积分撤单冲正
				self.Command = 13
			else:
				return False

			self.fld25 = self.parseObj.getBit(25)

			ret = self.verify(mc)
			if not ret:	#校验MAC
				return False
			if isinstance(ret, str):
				return ret

			#获取卡号
			'''
			if not self.parseCard(mc):
				if self.CardNo is None or len(self.CardNo) < 11:
					self.CardNo = '01000000000'	#TODO:这个逻辑需要修改，获取card_db这是必须的
				if self.pwd is None:
					self.pwd = ''
			'''
			try:
				self.CardNo = self.parseObj.getBit(2)[-11:]
			except:
				return False	#数据库要求账号作检查，如果没有2域应该是返回失败
			#获取操作员
			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = oper[-3:]
			except:
				self.oper = ''

			#冲正原因
			self.czCode = self.parseObj.getBit(39)
			#原单号批次号
			self.orgSerial = self.PosSerial
			try:
				pos, self.orgTransType = self.parseObj.getBitNext(60, 0, ('N', 2))
				pos, self.orgBatch = self.parseObj.getBitNext(60, pos, ('N', 6))
			except:
				posp.logger.exception('%s PV reserve' % self.addr)
				return False

			try:
				self.je = int(self.parseObj.getBit(4))
			except:
				self.je = 0;

		elif self.mt == 500:		#批结算
			self.Command = 11

			if self.PosNo is None or self.EntNo is None:
				posp.logger.error('%s: Batch Settlement error: non PosNo or EntNo' % self.addr)
				return False
			self.Currency = self.getBit(49)
			if self.Currency is None:
				posp.logger.error('%s: Batch Settlement error: non currency code' % self.addr)
				return False
			try:
				offset, self.TransType = self.parseObj.getBitNext(60, 0, ('N', 2))
				offset, self.batchNo = self.parseObj.getBitNext(60, offset, ('N', 6))
				offset, self.NMCode = self.parseObj.getBitNext(60, offset, ('N', 3))
			except:
				posp.logger.error('%s Batch settle, bit 60 is not set' % self.addr)
				return False
			if self.TransType is None or self.batchNo is None:
				posp.logger.error('%s: Batch Settlement error: batch number non set' % self.addr)
				return False
			try:
				offset, self.oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = self.oper[-3:]
			except:
				self.oper = ''
			#获取48域
			try:
				offset, _ = self.parseObj.getBitNext(48, 0, ('N', 12))
				offset, _ = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, _ = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, _ = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, inter5 = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, inter6 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, inter7 = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, inter8 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, _ = self.parseObj.getBitNext(48, offset, ('N', 1))
				self.jfze, self.jfbs, self.cdze, self.cdbs = int(inter5), int(inter6), int(inter7), int(inter8)

				offset, self.src48out1 = self.parseObj.getBitNext(48, 0, ('N', 12))
				offset, self.src48out2 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, self.src48out3 = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, self.src48out4 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, self.src48out5 = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, self.src48out6 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, self.src48out7 = self.parseObj.getBitNext(48, offset, ('N', 12))
				offset, self.src48out8 = self.parseObj.getBitNext(48, offset, ('N', 3))
				offset, self.src48out9 = self.parseObj.getBitNext(48, offset, ('N', 1))
			except:
				posp.logger.error('% bit 48 error' % self.addr)
				return False

		elif self.mt == 320:
			ret = self.verify(mc)
			if not ret:	#校验MAC
				return False
			if isinstance(ret, str):
				return ret

			#取60域用于判断操作
			try:
				offset, self.transType = self.parseObj.getBitNext(60, 0, ('N',2))
				offset, self.batchNo = self.parseObj.getBitNext(60, offset, ('N',6))
				offset, self.batchMod = self.parseObj.getBitNext(60, offset, ('N',3))
			except:
				posp.logger.error('%s domain 60 is not set'% self.addr)
				return False

			#操作员
			try:
				offset, self.oper = self.parseObj.getBitNext(63, 0, ('AN', 3))
				self.oper = self.oper[-3:]
			except:
				self.oper = ''

			if self.batchMod == '201':	#批上送
				self.Command = 16
				#获取48域内容,磁条卡N2,((N2,N6,N20,N12)...())
				try:
					offset, d = self.parseObj.getBitNext(48, 0, ('N', 2))
					self.mcNum = int(d)
					if self.mcNum > 8:	#最多8条数据
						posp.logger.error('%s: magicard too many entries' % (self.addr))
						return False
					i = self.mcNum
					self.mcDeals = []
					while i > 0:
						offset, d1 = self.parseObj.getBitNext(48, offset, ('N', 2))
						offset, d2 = self.parseObj.getBitNext(48, offset, ('N', 6))
						offset, d3 = self.parseObj.getBitNext(48, offset, ('N', 20))
						offset, d4 = self.parseObj.getBitNext(48, offset, ('N', 12))
						self.mcDeals.append([d1, d2, d3, d4])
						i -= 1

					#积分卡交易N2,((N6,N11,N12,N4,N12,N12),....())
					offset, d = self.parseObj.getBitNext(48, offset, ('N', 2))
					self.pcNum = int(d)
					if self.pcNum > 8:	#最多8条数据
						posp.logger.error('%s: points card too many entries' % (self.addr))
						return False
					#获取积分卡数据
					self.pcDeals = []
					for x in xrange(self.pcNum):
						offset, ent1 = self.parseObj.getBitNext(48, offset, ('N', 6))
						offset, ent2 = self.parseObj.getBitNext(48, offset, ('N', 20))
						offset, ent3 = self.parseObj.getBitNext(48, offset, ('N', 12))
						offset, ent4 = self.parseObj.getBitNext(48, offset, ('N', 4))
						offset, ent5 = self.parseObj.getBitNext(48, offset, ('N', 12))
						offset, ent6 = self.parseObj.getBitNext(48, offset, ('N', 12))
#						if ent1 is None or ent2 is None or ent3 is None or ent4 is None or ent5 is None or ent6 is None:
#							posp.logger.error('%s: points card number is %d, but datum gotten None' % (self.addr, self.pcNum))
#							return False
#						else:
						#参数规整#积分金额和积分在撤单时需要设置为负数
						je = int(ent3)/100.0
						bl = int(ent4)/10000.0
						jfje = int(ent5)/100.0
						jf = int(ent6)/100.0
						if je <= 0.0:
							jfje = -jfje
							jf = -jf
						self.pcDeals.append([ent1, ent2[-11:], je, bl, jfje, jf])
				except:
					posp.logger.exception('%s ' % self.addr)
					return False

			elif self.batchMod == '203':	#批上传通知
				posp.logger.debug('%s: mode %s did not surpport now' % (self.addr, self.batchMod))

			elif self.batchMod == '207' or self.batchMod == '202':	#批上传结束
				self.Command = 17
				try:
					offset, d = self.parseObj.getBitNext(48, 0, ('N', 4))
					self.counts = int(d)
				except:
					posp.logger.exception('%s Batch upload finished ' % self.addr)
					return False

			else:
				posp.logger.exception('%s: Unkown batch mode: %s' % (self.addr, self.batchMod))
				return False

		elif self.mt == 950:			#同步参数/上传参数
			ret = self.verify(mc)
			if not ret:	#校验MAC
				return False
			if isinstance(ret, str):
				return ret

			#操作员
			try:
				offset, oper = self.parseObj.getBitNext(63, 0, ('N', 3))
				self.oper = oper[-3:]
			except:
				self.oper = ''

			#操作字
			try:
				self.op = self.parseObj.getBit(3)[0:2]
			except:
				posp.logger.error('%s Syn variables bit 3 is not set' % self.addr)
				return False

			if self.op == '72':				#同步
				self.Command, self.PosCode = 14, ''
				try:
					self.PosSerial = self.parseObj.getBit(11)
					offset, self.baseVer = self.parseObj.getBitNext(62, 0, ('N', 4))
					offset, self.currencyVer = self.parseObj.getBitNext(62, offset, ('N', 4))
					offset, self.countryVer = self.parseObj.getBitNext(62, offset, ('N', 4))
				except:
					posp.logger.error('%s Syn vars bit 11 or 62 is not set' % self.addr)
					return False

				if self.baseVer is None or len(self.baseVer) <= 0 or\
						self.currencyVer is None or len(self.currencyVer) <= 0 or\
						self.countryVer is None or len(self.countryVer) <= 0:
					posp.logger.error('%s Syn vars versions is not set' % self.addr)
					return False

			elif self.op == '73':			#上传
				self.Command = 15
				#解析48：n2(n4...n4)(5)
				try:
					offset, d = self.parseObj.getBitNext(48, 0, ('N', 2))
					self.jfblNum = int(d)
					if self.jfblNum > 5 or self.jfblNum <= 0:	#积分比例最多5个,没有也认为错误
						posp.logger.error('%s: %s:%s points ratio count %d' % (self.addr, self.EntNo, self.PosNo, self.jfblNum))
						return False
					offset, d1 = self.parseObj.getBitNext(48, offset, ('N', 4))
					offset, d2 = self.parseObj.getBitNext(48, offset, ('N', 4))
					offset, d3 = self.parseObj.getBitNext(48, offset, ('N', 4))
					offset, d4 = self.parseObj.getBitNext(48, offset, ('N', 4))
					offset, d5 = self.parseObj.getBitNext(48, offset, ('N', 4))
					self.jfbls = (d1, d2, d3, d4, d5)
				except:
					posp.logger.error('%s update ratios bit 48' % self.addr)
					return False
				#检查积分比例
				for ent in self.jfbls:
					jfbl = int(ent)/10000.0
					if jfbl > 0.3 or jfbl < 0.0001:
						posp.logger.error('%s: %s:%s points ratio out of range %.4f' % (self.addr, self.EntNo, self.PosNo, self.jfblNum))
						return False
		else:
			return False

		return True

	def packet(self, status, **args):
		mc = args.get('MEMCACHED', None)
		now = time.localtime(time.time())
		needMAC = False

		self.timer.count()
		retobj = Py8583()
		#如果有错误信息，那么也应该把它转成gbk编码
		if self.ErrInfo is not None:
			self.ErrInfo = self.ErrInfo.decode('utf8').encode('gbk')
		if status != '0000':
			posp.logger.warning('Command %d return status: %s, 交易流水号: %s' % (self.Command, status, self.serialno))

		if self.Command == 1:		#积分
			retobj.mti = 910
			if len(self.CardNo) == 15:
				retobj.setBit(2, self.CardNo[0:11])
			else:
				retobj.setBit(2, self.CardNo)
			retobj.setBit(3, self.op+'0001')
			retobj.setBit(4, str(self.je))
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(25, self.fld25)
			retobj.setBit(32, self.CardNo[0:2]+'000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.setBit(49, '%d' % self.currency)
			retobj.addBit(60, ('N', 2, self.TransType))
			retobj.addBit(60, ('N', 6, self.orgBatch))
			retobj.addBit(63, ('AN', 3, 'GYT'))
			if status == '0000':
				self.bcjf = str(self.bcjf)
				retobj.addBit(63, ('LL', len(self.bcjf), self.bcjf))
			else:		#错误报文
				retobj.setBit(62, self.ErrInfo) #这里是错误信息
			needMAC = True

		elif self.Command == 2:			#积分撤单
			retobj.mti = 910
			retobj.setBit(2, self.CardNo[0:11])
			retobj.setBit(3, self.op+'0000')
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(15, '0000')
			retobj.setBit(25, self.fld25)
			retobj.setBit(32, self.CardNo[0:2]+'000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.addBit(60, ('N', 2, self.f601))
			retobj.addBit(60, ('N', 6, self.batch))
			retobj.addBit(63, ('AN', 3, 'GYT'))
			if status == '0000':
				retobj.addBit(48, ('N', 4, str(self.jfbl)))
				retobj.addBit(48, ('N', 12, str(self.jfje)))
				self.bcjf = str(self.bcjf)
				retobj.addBit(63, ('LL', len(self.bcjf), self.bcjf))
			else:
				retobj.setBit(62, self.ErrInfo) 	#错误信息
			needMAC = True

		elif self.Command == 3:
			retobj.mti = 930
			retobj.setBit(2, self.CardNo[0:11])
			retobj.setBit(3, self.op+'0001')
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(25, self.fld25)
			retobj.setBit(32, self.CardNo[0:8])
			retobj.setBit(39, status[-2:])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			#48域
			#卡号,总条数
			retobj.addBit(48, ('N', 11, self.CardNo[0:11]))
			retobj.addBit(48, ('N', 2, str(self.count)))
			for ent in self.presDial:
				jfje = int(ent['PV_MONEY']*100)
				jyje = int(ent['MONEY']*100)
				if jyje > 0:	#积分金额大于0表示积分交易
					transType = '61'
					transCode = '210000'
					centerSerial = ent['TRANS_NO'][-12:]
					bcjf = int(ent['POINT_THIS']*100)
				else:					#撤单交易
					transType = '62'
					transCode = '200000'
					centerSerial = ent['CANCEL_TRANS_NO'][-12:]
					bcjf = int(ent['POINT_THIS']*-100)
					jfje = -jfje

				transTime = ent['TRANS_TIME'].split(' ')[1].replace(':', '')
				#交易类型n4，交易处理码n6，POS机交易流水号n6，交易时间n6，POS中心参考号ans12，
				#应答标志n2，终端编号ans8，
				#消费金额n12，积分比例n4，积分金额n12，操作员编号n3，本次积分数n12，交易批次号n6
				retobj.addBit(48, ('N', 4, transType))
				retobj.addBit(48, ('N', 6, transCode))
				retobj.addBit(48, ('N', 6, ent['TRADE_NO']))
				retobj.addBit(48, ('N', 6, transTime))
				retobj.addBit(48, ('ANS', 12, centerSerial))
				retobj.addBit(48, ('N', 2, str(ent['TRANS_FLAG'])))
				retobj.addBit(48, ('ANS', 8, ent['POS_NO'][-2:]))
				retobj.addBit(48, ('N', 12, str(jyje)))
				retobj.addBit(48, ('N', 4, str(int(ent['POINT_RATIO']*10000))))
				retobj.addBit(48, ('N', 12, str(jfje)))
				retobj.addBit(48, ('N', 3, ent['OPERATOR_NAME']))
				retobj.addBit(48, ('N', 12, str(bcjf)))
				retobj.addBit(48, ('N', 6, ent['BAT_NO']))

			retobj.addBit(60, ('N', 2, self.transType))
			retobj.addBit(60, ('N', 6, self.batchNo))
			if status != '0000' or self.count <= 0:
				if self.count <= 0:
					retobj.setBit(39, '90')
				retobj.setBit(62, self.ErrInfo)		#错误信息

			needMAC = True

		elif self.Command == 6:
			retobj.mti = 930
			retobj.setBit(3, '710001')
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(37, self.orgSerial)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.addBit(60, ('N', 2, self.transType))
			retobj.addBit(60, ('N', 6, self.batchNo))

			if status == '0000':
				self.CardNo=self.detail['CARD_NO'][0:11]
				retobj.setBit(32, self.CardNo[0:8])
				jfje = int(self.detail['PV_MONEY']*100)
				jyje = int(self.detail['MONEY']*100)
				if jyje > 0:	#积分金额大于于0表示积分交易
					transType = '61'
					transCode = '210000'
					centerSerial = self.detail['TRANS_NO'][-12:]
					bcjf = int(self.detail['POINT_THIS']*100.0)
				else:					#撤单
					transType = '62'
					transCode = '200000'
					centerSerial = self.detail['CANCEL_TRANS_NO'][-12:]
					bcjf = int(self.detail['POINT_THIS']*-100.0)
					jfje = -jfje

				transTime = self.detail['TRANS_TIME'].split(' ')[1].replace(':', '')
				#卡号n19，交易类型n4，交易处理码n6，POS机交易流水号n6，交易时间n6，POS中心参考号ans12，
				#应答标志n2，终端编号ans8，
				#消费金额n12，积分比例n4，积分金额n12，操作员编号n3，本次积分数n12，交易批次号n6
				posno = self.detail['POS_NO'][-2:]
				retobj.addBit(48, ('N', 11, self.CardNo))
				retobj.addBit(48, ('N', 4, transType))
				retobj.addBit(48, ('N', 6, transCode))
				retobj.addBit(48, ('N', 6, self.detail['TRADE_NO']))
				retobj.addBit(48, ('N', 6, transTime))
				retobj.addBit(48, ('ANS', 12, centerSerial))
				retobj.addBit(48, ('N', 2, str(self.detail['TRANS_FLAG'])))
				retobj.addBit(48, ('ANS', 8, posno))
				retobj.addBit(48, ('N', 12, str(jyje)))
				retobj.addBit(48, ('N', 4, str(int(self.detail['POINT_RATIO']*10000))))
				retobj.addBit(48, ('N', 12, str(jfje)))
				retobj.addBit(48, ('N', 3, self.detail['OPERATOR_NAME']))
				retobj.addBit(48, ('N', 12, str(bcjf)))
				retobj.addBit(48, ('N', 6, self.detail['BAT_NO']))
				needMAC = True
			else:
				retobj.setBit(62, self.ErrInfo)
				if status[-2:] == '10':
					needMAC = True

		elif self.Command == 9:
			retobj.mti = 810
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(32, self.EntNo[0:2]+'000000')
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			if status == '0000':
				retobj.setBit(37, self.serialno)
				retobj.addBit(60, ('N', 2, '00'))
				retobj.addBit(60, ('N', 6, self.batchNo))
				retobj.addBit(60, ('N', 3, '003'))
				retobj.setBit(62, self.pinKey+self.macKey)
			else:
				retobj.setBit(62, self.ErrInfo)

		elif self.Command == 10:
			retobj.mti = 830
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(32, self.EntNo[0:2]+'000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.addBit(60, ('N', 2, '00'))
			retobj.addBit(60, ('N', 6, self.fld60_2))
			retobj.addBit(60, ('N', 3, '002'))

		elif self.Command == 11:		#批处理
			retobj.mti = 510
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(15, '0000')
			retobj.setBit(32, self.EntNo[0:2]+'000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			#TODO:返回8个元素的数组还是8个独立数
			retobj.addBit(48, ('N', 12, '0'))
			retobj.addBit(48, ('N', 3, '0'))		#借记
			retobj.addBit(48, ('N', 12, '0'))
			retobj.addBit(48, ('N', 3, '0'))		#贷记
			retobj.addBit(48, ('N', 12, str(self.jfze)))
			retobj.addBit(48, ('N', 3, str(self.jfbs)))		#积分
			retobj.addBit(48, ('N', 12, str(self.cdze)))
			retobj.addBit(48, ('N', 3, str(self.cdbs)))		#撤单
			retobj.addBit(48, ('N', 1, self.BalAcc))
			#外卡数据，不作结算，直接返回1
			retobj.addBit(48, ('N', 12, self.src48out1))
			retobj.addBit(48, ('N', 3, self.src48out2))
			retobj.addBit(48, ('N', 12, self.src48out3))
			retobj.addBit(48, ('N', 3, self.src48out4))
			retobj.addBit(48, ('N', 12, self.src48out5))
			retobj.addBit(48, ('N', 3, self.src48out6))
			retobj.addBit(48, ('N', 12, self.src48out7))
			retobj.addBit(48, ('N', 3, self.src48out8))
			retobj.addBit(48, ('N', 1, '1'))
			retobj.addBit(60, ('N', 2, self.TransType))
			retobj.addBit(60, ('N', 6, self.batchNo))
			retobj.addBit(60, ('N', 3, self.NMCode))
			if status != '0000':
				retobj.setBit(62, self.ErrInfo)		#错误
			retobj.addBit(63, ('N', 3, 'GYT'))

		elif self.Command == 12 or self.Command == 13:		#积分冲正\积分撤单冲正
			retobj.mti = 410
			retobj.setBit(2, self.CardNo)
			retobj.setBit(3, self.op + '0000')
			retobj.setBit(4, '%d' % self.je)
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(25, self.fld25)
			retobj.setBit(32, self.CardNo[0:2]+'000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.addBit(60, ('N', 2, self.orgTransType))
			retobj.addBit(60, ('N', 6, self.orgBatch))

			if status != '0000' or self.ReverRes != 'Y':
				retobj.setBit(62, self.ErrInfo)	#错误信息

			retobj.addBit(63, ('AN', 3, 'GYT'))
			needMAC = True

		elif self.Command == 14:			#同步参数
			retobj.mti = 960
			retobj.setBit(3, self.op+'0001')
			retobj.setBit(11, self.PosSerial)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			if status != '0000':
				retobj.setBit(62, self.ErrInfo)		#错误信息
			else:
				#企业信息
				retobj.addBit(62, ('N', 4, self.baseDBVer))
				self.entDBName = self.entDBName.decode('utf8').encode('gbk')
				retobj.addBit(62, ('ANS', 40, self.entDBName))
				retobj.addBit(62, ('ANS', 25, self.entDBPhone))
				retobj.addBit(62, ('ANS', 30, self.entDBWeb))
				#货币,操作条数;;(n2, n3, ans10)
				retobj.addBit(62, ('N', 4, self.currDBVer))
				if int(self.currDBVer) != int(self.currencyVer):
					for ent in self.currencys:
						retobj.addBit(62, ('N', 2, str(ent[0])))
						retobj.addBit(62, ('N', 3, ent[1]))
						retobj.addBit(62, ('ANS', 10, ent[2]))
				#国家
				if self.countryNum > 50:	#TODO:
					self.countryNum=50
				retobj.addBit(62, ('N', 4, self.countryDBVer))
				retobj.addBit(62, ('N', 2, str(int(self.countryNum))))
				i = 0
				while i < self.countryNum:
					retobj.addBit(62, ('N', 3, str(self.countrys[i][0])))
					retobj.addBit(62, ('N', 3, self.countrys[i][1]))
					retobj.addBit(62, ('N', 1, str(self.countrys[i][2])))
					i += 1
				retobj.addBit(63, ('AN', 3, 'GYT'))

		elif self.Command == 15:			#上传参数
			retobj.mti = 960
			retobj.setBit(3, self.op+'0001')
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(37, self.EntNo[0:2])
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			if status != '0000':
				retobj.setBit(62, self.ErrInfo)

		elif self.Command == 16:			#批上送
			retobj.mti = 330
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(32, self.EntNo[0:2] + '000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			batchMod = '206'
			if status != '0098' and self.BalAcc == '1':
				batchMod = '207'
			retobj.addBit(60, ('N', 2, self.transType))
			retobj.addBit(60, ('N', 6, self.batchNo))
			retobj.addBit(60, ('N', 3, batchMod))

		elif self.Command == 17:			#批上送结束
			retobj.mti = 330
			retobj.setBit(12, time.strftime('%H%M%S', now))
			retobj.setBit(13, time.strftime('%m%d', now))
			retobj.setBit(32, self.EntNo[0:2] + '000000')
			retobj.setBit(37, self.serialno)
			retobj.setBit(39, status[2:4])
			retobj.setBit(41, self.PosNo)
			retobj.setBit(42, self.EntNo)
			retobj.addBit(48, ('N', 4, str(self.counts)))
			retobj.addBit(60, ('N', 2, self.transType))
			retobj.addBit(60, ('N', 6, self.batchNo))
			retobj.addBit(60, ('N', 3, self.batchMod))

		#添加MAC域
		if needMAC:
			retobj.setBit(64, '00000000')
			retstr = retobj.getRawIso()
			mac = self.getMac(retstr[0:-8], mc)
			if mac is None:
				return False
			retobj.setBit(64, mac[0:8])
		self.timer.count('Pack')
		return retobj.getRawIso()

	@property
	def typeName(self):
		return self.Command

	def onAnswer(self, data):
		if self.needSignAgain:
			retstr = struct.pack('!H', len(data)+11) + self.XGDTPDU + data
		else:
			retstr = struct.pack('!H', len(data)+11) + self.XGDTPDU_SIGN + data
		return retstr
