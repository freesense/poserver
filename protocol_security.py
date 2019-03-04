#!/usr/bin/python2.6
#coding: utf-8

'''与安全服务器通讯协议
'''

import posp, struct, security
from posp import cut

class Pack_security(posp.PacketBase):
	'''与安全服务器之间的通讯协议定义
	'''

	DATAFLAG = '\x60\x60'

	def addData(self, data):
		head, self.data = data[0:2], data[2:]
		if head != self.DATAFLAG:
			return False
		return True

	@property
	def typeName(self):
		return self.Command

	def parse(self, **args):
		self.addr, self.timer = str(args.get('PEER', 'Unknown')), args.get('TIMER', None)
		self.timer.count()

		self.reqNo = struct.unpack_from('!H', self.data[2:])[0]
		d = self.data[2:].split('&')
		if d[0] != 'GetKeys':
			return False
		self.Command, self.oper, self.EntNo, self.PosNo = 19, d[1], '', ''

		self.timer.count('Unpack')
		return True

	def packet(self, status, **args):
		mc = args.get('MEMCACHED', None)
		mac = ''
		self.timer.count()

		try:
			mac = security.CRYPTOR.getMac(self.EntNo, self.PosNo, self.oper, self.data, mc, self.timer)
		except:
			posp.logger.exception('getMac Error')
			self.data = ''
		finally:
			self.timer.count('Pack')

		return mac + self.data

	def onAnswer(self, data):
		return struct.pack('!H', len(data)) + data
