#!/usr/bin/python2.6
#coding: utf-8

'''新国都密钥灌录业务
'''

import posp, struct, security
from posp import cut

class Pack_xgd_pos(posp.PacketBase):
	'''灌录新国都POS机密钥业务
	由PC程序代理POS机向中间件请求订单号码、企业资源号、POS机编号数据
	'''

	EntNo, PosNo, Command = None, None, 0,

	XGDPOSINITFLAG = '\x60\xff'
	dictCommands = {
		'GetOrders' : 7,
		'GetPos'	: 8,
		'GetEnt'	: 4,
		'PosCfg'  	: 18
	}

	def addData(self, data):
		head, self.data = data[0:2], data[2:]
		if head != self.XGDPOSINITFLAG:
			return False
		return True

	def parsePwd(self, mc):
		try:
			self.pwd = security.CRYPTOR.decrypt('', '', self.oper, self.pwd, mc, self.timer)
		except:
			posp.logger.exception('decrypt Error')
			return False
		else:
			return True

	def checkMac(self, mc, mac, d):
		_mac = ''
		try:
			_mac = security.CRYPTOR.getMac('', '', self.oper, d, mc, self.timer)
		except:
			posp.logger.exception('getMac Error')
			return False

		if _mac != mac:
			posp.logger.warning('mac error!')
			return False
		else:
			return True

	def parse(self, **args):
		self.addr, self.timer, mc = str(args.get('PEER', 'Unknown')), args.get('TIMER', None), args.get('MEMCACHED', None)
		self.timer.count()

		mac, d = self.data[0:8], self.data[8:]

		self.Command, self.data = self.data[8:].split('&', 1)
		self.Command = self.dictCommands.get(self.Command, None)
		if self.Command is None:
			posp.hexdump(self.data, 'Invalid Command')
			self.timer.count('Unpack')
			return False

		try:
			if self.Command == 7:
				self.oper, self.pwd = struct.unpack_from('!16s32s', self.data)
				self.oper = cut(self.oper)
				self.EntNo = self.oper.split('_')[1]+'000000000'
				if not self.parsePwd(mc):
					return False

			elif self.Command == 8:
				self.oper, self.pwd = struct.unpack_from('!16s32s', self.data)
				self.oper = cut(self.oper)
				self.OrderNo = cut(self.data[struct.calcsize('!16s32s'):])
				self.EntNo = self.oper.split('_')[1]+'000000000'
				if not self.parsePwd(mc):
					return False

			elif self.Command == 4:
				self.oper, self.pwd, self.EntNo, self.PosNo, self.PosCode = struct.unpack_from('!16s32s11s2s16s', self.data)
				self.oper, self.EntNo, self.PosNo, self.PosCode = cut(self.oper), cut(self.EntNo), cut(self.PosNo), cut(self.PosCode)
				if not self.parsePwd(mc):
					return False

			elif self.Command == 18:
				self.oper, self.pwd, self.EntNo, self.PosNo, self.PosCode, self.operation_result = struct.unpack_from('!16s32s11s2s16sc', self.data)
				self.oper, self.EntNo, self.PosNo, self.PosCode, self.operation_result = cut(self.oper), cut(self.EntNo), cut(self.PosNo), cut(self.PosCode), cut(self.operation_result)
				if not self.parsePwd(mc):
					return False

		except:
			posp.logger.error('Error format')
			self.timer.count('Unpack')
			return False

		check = self.checkMac(mc, mac, d)

		self.timer.count('Unpack')
		return check

	def packet(self, status, **args):
		mc = args.get('MEMCACHED', None)
		self.timer.count()
		s = None
		if self.Command == 4:
			if status == '0000' or status == '0010':
				#baseVer, moneyVer, countryVer
				b = '%04d%04d%04d' % (int(self.baseVer), int(self.moneyVer), int(self.countryVer))
				self.EntName = self.EntName.decode('utf8').encode('gbk')
				l = struct.pack('40s25s30s', self.EntName, self.phone, self.url) + ''.join(self.currency)
				s = b + l + struct.pack('!2H', int(status), len(self.country)) + ''.join(self.country)
			else:
				s = ''

		elif self.Command == 7:
			s = struct.pack('!H', self.count) + ''.join(self.applist)
			del self.applist

		elif self.Command == 8:
			s = struct.pack('!H', len(self.poslist)) + ''.join([struct.pack('!2s1s', p[-2:], s) for p, s in self.poslist])
			del self.poslist

		elif self.Command == 18:
			if status == '0000':
				s = '0'
			else:
				s = '1'

		_mac = ''
		try:
			_mac = security.CRYPTOR.getMac('', '', self.oper, s, mc, self.timer)
		except:
			posp.logger.exception('getMac Error')

		self.timer.count('Pack')
		return _mac + s

	@property
	def typeName(self):
		return self.Command

	def onAnswer(self, data):
		d = '\x60\xff' + data
		return struct.pack('!H', len(d)) + d
