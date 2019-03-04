#!/usr/bin/python2.6
#coding: utf-8

'''安全线实现
'''

import cPickle, random, struct, gevent, socket, posp
from ctypes import *
from gyconfig import *

###############################################################################
class crypto_fake:
	def getKey(self, EntNo, PosNo, oper, mc, timer):
		return '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00', '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

	def getMac(self, EntNo, PosNo, oper, data, mc, timer):
		return data[-8:]

	def encrypt(self, EntNo, PosNo, oper, data, mc, timer):
		return data

	def decrypt(self, EntNo, PosNo, oper, data, mc, timer):
		return data

	def bind_req(self, EntNo, PosNo, oper, data, pin, mc, timer):
		return '00000000', pin

class crypto_gydes:
	modCrypt = CDLL('./gydes.so')		## 加解密模块

	def getKey(self, EntNo, PosNo, oper, mc, timer):
		k = 'key.%s.%s' % (EntNo, PosNo)
		pmk = '\xdf\x59\x70\x5e\x46\xa8\x2b\x8e\x70\x66\x51\x8d\xa5\x18\x45\x37'
		pik = ''.join([chr(random.randint(0, 255)) for x in xrange(16)])
		mak = ''.join([chr(random.randint(0, 255)) for x in xrange(8)])
		timer.count()
		mc.set(k, cPickle.dumps((pmk, pik, mak)))
		timer.count('mc')

		pikdes, makdes = create_string_buffer(16), create_string_buffer(8)
		self.modCrypt.DES3_encrypt(c_char_p(pik), c_char_p(pmk), pikdes, c_int(16))
		self.modCrypt.DES3_encrypt(c_char_p(mak), c_char_p(pmk), makdes, c_int(8))

		pikcheck, makcheck = create_string_buffer(8), create_string_buffer(8)
		self.modCrypt.DES3_encrypt(c_char_p('\x00\x00\x00\x00\x00\x00\x00\x00'), c_char_p(pik), pikcheck, c_int(8))
		self.modCrypt.DES_encrypt(c_char_p('\x00\x00\x00\x00\x00\x00\x00\x00'), c_char_p(mak), makcheck, c_int(8), c_int(0))

		timer.count('keys')
		return pikdes.raw+pikcheck.raw[0:4], makdes.raw+'\x00\x00\x00\x00\x00\x00\x00\x00'+makcheck.raw[0:4]

	def getMac(self, EntNo, PosNo, oper, data, mc, timer):
		k = 'key.%s.%s' % (EntNo, PosNo)
		timer.count()
		allkeys = mc.get(k)
		timer.count('mc')
		pmk, pik, mak = cPickle.loads(allkeys)
		mac = create_string_buffer(16)
		self.modCrypt.DES3_Mac(c_char_p(mak), c_char_p(data[0:-8]), c_int(len(data)-8), mac)
		timer.count('makemac')
		return mac.raw[0:8]

	def encrypt(self, EntNo, PosNo, oper, data, mc, timer):
		k = 'key.%s.%s' % (EntNo, PosNo)
		timer.count()
		allkeys = mc.get(k)
		timer.count('mc')
		pmk, pik, mak = cPickle.loads(allkeys)
		buf = create_string_buffer(len(data))
		self.modCrypt.DES3_encrypt(c_char_p(data), c_char_p(pik), buf, c_int(len(data)))
		timer.count('encrypt')
		return buf.raw

	def decrypt(self, EntNo, PosNo, oper, data, mc, timer):
		k = 'key.%s.%s' % (EntNo, PosNo)
		timer.count()
		allkeys = mc.get(k)
		timer.count('mc')
		pmk, pik, mak = cPickle.loads(allkeys)
		buf = create_string_buffer(len(data))
		self.modCrypt.DES3_decrypt(c_char_p(data), c_char_p(pik), buf, c_int(len(data)))
		timer.count('decrypt')
		return buf.raw

	def bind_req(self, EntNo, PosNo, oper, data, pin, mc, timer):
		k = 'key.%s.%s' % (EntNo, PosNo)
		timer.count()
		allkeys = mc.get(k)
		timer.count('mc')
		pmk, pik, mak = cPickle.loads(allkeys)
		mac, buf = create_string_buffer(16), create_string_buffer(len(data))
		self.modCrypt.DES3_Mac(c_char_p(mak), c_char_p(data), c_int(len(data)), mac)
		self.modCrypt.DES3_decrypt(c_char_p(pin), c_char_p(pik), buf, c_int(len(data)))
		timer.count('bind')
		return mac.raw[0:8], buf.raw

class crypto_standalone:
	def __init__(self):
		self.svrs, self.svridx = CRYPTOSVR, 0
		random.shuffle(self.svrs)

	def connect(self):
		s = socket.socket()

		while 1:
			try:
				svr = self.svrs[self.svridx]
			except IndexError:
				self.svridx = 0
				continue
			else:
				self.svridx += 1

			try:
				s.connect(svr)
			except:
				posp.logger.exception('Connect to %s failed.' % str(svr))
				continue

			break

		return s

	def recv(self, s, l):
		d, recvd = '', ''
		while len(d) < l:
			try:
				recvd = s.recv(l - len(d))
			except:
				return None
			if len(recvd) == 0:
				return None
			d += recvd
		return d

	def getKey(self, EntNo, PosNo, oper, mc, timer):
		s = self.connect()
		d = struct.pack('!11s2s16s', EntNo, PosNo, oper)
		d = struct.pack('!2BH', 0, 0x11, len(d)) + d

		sss = s.send(d)

		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			l = self.recv(s, 4)
		if l is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		unuse, msgtype, l = struct.unpack('!2BH', l)
		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			d = self.recv(s, l)
		if d is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		s.close()

		pik, mak = struct.unpack('20s20s', d)
		return pik, mak

	def getMac(self, EntNo, PosNo, oper, data, mc, timer):
		'''data是要做MAC的数据
		'''
		s = self.connect()
		d = struct.pack('!11s2s16s', EntNo, PosNo, oper) + data
		d = struct.pack('!2BH', 0, 0x12, len(d)) + d
		sss = s.send(d)

		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			l = self.recv(s, 4)
		if l is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		unuse, msgtype, l = struct.unpack('!2BH', l)
		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			d = self.recv(s, l)
		if d is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		s.close()

		return d

	def encrypt(self, EntNo, PosNo, oper, data, mc, timer):
		s = self.connect()
		d = struct.pack('!11s2s16s', EntNo, PosNo, oper) + data
		d = struct.pack('!2BH', 0, 0x13, len(d)) + d
		sss = s.send(d)

		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			l = self.recv(s, 4)
		if l is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		unuse, msgtype, l = struct.unpack('!2BH', l)
		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			d = self.recv(s, l)
		if d is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		s.close()

		return d

	def decrypt(self, EntNo, PosNo, oper, data, mc, timer):
		s = self.connect()
		d = struct.pack('!11s2s16s', EntNo, PosNo, oper) + data
		d = struct.pack('!2BH', 0, 0x14, len(d)) + d
		sss = s.send(d)

		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			l = self.recv(s, 4)
		if l is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		unuse, msgtype, l = struct.unpack('!2BH', l)
		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			d = self.recv(s, l)
		if d is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		s.close()

		return d

	def bind_req(self, EntNo, PosNo, oper, data, pin, timer):
		s = self.connect()
		d = struct.pack('!11s2s16sH', EntNo, PosNo, oper, len(data)) + data + struct.pack('!H', len(pin)) + pin
		d = struct.pack('!2BH', 0, 0x15, len(d)+4) + d
		sss = s.send(d)

		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			l = self.recv(s, 4)
		if l is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		unuse, msgtype, l = struct.unpack('!2BH', l)
		with gevent.Timeout(CLIENT_TIMEOUT, False) as timeout:
			d = self.recv(s, l)
		if d is None:
			s.close()
			raise Exception('Recv %s Error' % str(CRYPTOSVR))
		s.close()

		l = struct.unpack('!H', d)[0]
		desd, d = d[2:2+l], d[2+l:]
		l = struct.unpack('!H', d)[0]
		macd = d[2:2+l]

		return macd, desd

################################################################################
#安全线配置
#加密模块,可配置crypto_standalone\crypto_fake\crypto_gydes
CRYPTOR = crypto_standalone()
#CRYPTOR = crypto_fake()