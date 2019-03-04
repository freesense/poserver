#!/usr/bin/python2.6
#coding: utf-8
import sys
if not "/home/midware/py" in sys.path:
     sys.path.append("/home/midware/py")
import struct, random, unittest, socket, sys, timeit, memcache, cPickle
from ctypes import *
from multiprocessing import *
from GY8583 import GY8583, str2bcd

SERVER = ('192.168.1.116', 11717)
SCOUNT = 0
VER = '0.9'
ENCRYPT = True
key = ''
FMT_PLAINTEXT = '!2H16s16s'
PLAIN_BLOCK_SIZE = struct.calcsize(FMT_PLAINTEXT)

#加解密
EntNo = '01006002092'
PosNo = '01'
#PMK='\xdf\x59\x70\x5e\x46\xa8\x2b\x8e\x70\x66\x51\x8d\xa5\x18\x45\x37'
PMK='\x47\x02\x13\x27\xa2\xfc\xbb\x06\xd3\x1e\xdb\x87\x09\xa7\x42\x48'
modCrypt = CDLL('../gydes.so')
mc = memcache.Client(['192.168.1.116:11211'])
mckey = 'pos.unit.test.' + '%s%s' % (EntNo, PosNo)

#测试用例初始条件，在这里增加测试条件的组合
#企业资源号，POS机编号，积分卡号+序列号，操作员号
unit01 = ('01001010000', '03', '010010100010001', '42', '')	#正常
#unit02 = ('01001010000', '03', '010010100019999', '42', '')	#错误的序列号
#unit03 = ('01001010000', '03', '990010100010001', '42', '')	#错误的积分卡号
#unit04 = ('01001010000', '99', '010010100010001', '42', '')	#错误的POS机编号
#unit05 = ('99001010000', '03', '010010100010001', '42', '')	#错误的企业资源号
#unit06 = ('', '03', '010010100010001', '42', '')			#企业资源号null
#unit07 = ('10001010000', '03', '010010100010001', '42', '')	#积分预付款不足

#压力测试用
entnos = []

#积分业务流水号
PVSERIAL = None
PVUNIT = None

def bcd2dec(bcd):
	'''
	BCD码转十进制
	bcd - BCD字符串
	return - 十进制数字
	'''
	dec = 0
	for x, y in [(ord(x) >> 4, ord(x) % 16) for x in bcd]:
		dec = dec*100+x*10+y
	return dec

def dec2bcd(dec, length = 0):
	'''
	十进制转BCD码
	dec - 十进制数字
	return - BCD字符串
	'''
	def _slice(dec):
		while dec:
			x, dec = dec % 100, dec / 100
			h, l = x / 10, x % 10
			yield chr((h << 4) + l)

	bcd = []
	for x in _slice(dec):
		bcd.append(x)
	l = len(bcd)
	for x in xrange(l, length):
		bcd.append('\x00')
	bcd.reverse()
	return ''.join(bcd)

def cut(s):	#处理字符串，截掉尾部\0后面所有内容
	return s.split('\0', 1)[0]

def hexdump(data, text = 'Hexdump'):
	print '%s, length = %d' % (text, len(data))
	l, r, x = '', '', 0
	for c in data:
		l += '%02x ' % ord(c)
		if ord(c) >= 32 and ord(c) <= 126:
			r += c
		else:
			r += '.'
		x += 1
		if x == 16:
			print '%-48s%-16s' % (l, r)
			l, r, x = '', '', 0
	if len(r) > 0:
		print '%-48s%-16s' % (l, r)

def getCardNo():
	y1 = random.randint(1, 99)
	y2 = random.randint(1, 9999)
	return '01888%02d%04d0001' % (y1, y2)

def fillEntNo():
#	for x in xrange(9999):
#		entnos.append('0188800%04d' % (x+1,))
	for x in xrange(99):
		entnos.append('01888%02d0000' % (x+1,))

def getEntNo():
	return random.choice(entnos)
#	return '01001010000'

def hexdump(data, text ='Hexdump'):
	'''
	16进制输出，向logging模块输出
	data - 要输出的数据
	text - 输出标题
	lv - 输出级别
	'''
	if data is None:
		print '%s, None'% text
		return

	outs =[]
	outs.append('%s, length =%d'%(text, len(data)))
	l, r, x =[],[], 0
	for c in data:
		l.append('%02x '% ord(c))
		if ord(c)>= 32 and ord(c)<= 126:
			r.append(c)
		else:
			r.append('.')
		x += 1
		if x == 16:
			outs.append('%-48s%-16s'%(''.join(l),''.join(r)))
			l, r, x =[],[], 0
	if len(r)> 0:
		outs.append('%-48s%-16s'%(''.join(l),''.join(r)))
	outs ='\n'.join(outs)
	print outs

class crypto_gydes:
	Pik, Mak = None, None

	def parseKeys(self, ks):
		#PIK
		p = ks[0:20]
		pik = create_string_buffer(16)
		modCrypt.DES3_decrypt(c_char_p(p[0:16]), c_char_p(PMK), pik, c_int(16))
		self.Pik = pik.raw
		#检查4字节的checkvalue
		pikcheck = create_string_buffer(8)
		modCrypt.DES3_encrypt(c_char_p('\x00\x00\x00\x00\x00\x00\x00\x00'), c_char_p(self.Pik), pikcheck, c_int(8))
		if p[-4:] != pikcheck.raw[0:4]:
			print '校验PIK失败'
			mc.delete(mckey)
			return False
		#MAK
		m = ks[-20:]
		mak = create_string_buffer(8)
		modCrypt.DES3_decrypt(c_char_p(m[0:8]), c_char_p(PMK), mak, c_int(8))
		self.Mak = mak.raw
		#检查4字节的checkvalue
		makcheck = create_string_buffer(8)
		modCrypt.DES_encrypt(c_char_p('\x00\x00\x00\x00\x00\x00\x00\x00'), c_char_p(self.Mak), makcheck, c_int(8))
		if m[-4:] != makcheck.raw[0:4]:
			print '校验MAK失败'
			mc.delete(mckey)
			return False
		#解析成功，更新到memcache
		hexdump(ks, 'before parse keys')
		hexdump(pikcheck.raw[0:4], 'pik check value')
		hexdump(makcheck.raw[0:4], 'mak check value')
		hexdump(self.Pik, 'Parse PIK')
		hexdump(self.Mak, 'Parse MAK')
		ret = mc.set(mckey, cPickle.dumps((self.Pik, self.Mak)))
		print 'memcache set:', mckey, ret

	def getKeys(self):
		allkeys = mc.get(mckey)
		if allkeys is None:
			return False
		self.Pik, self.Mak = cPickle.loads(allkeys)
		hexdump(self.Pik, 'memcache pik')
		hexdump(self.Mak, 'memcache mak')
		return True

	def getMac(self, data):
		if self.Mak is None:
			allkeys = mc.get(mckey)
			self.Pik, self.Mak = cPickle.loads(allkeys)
		mac = create_string_buffer(16)
		modCrypt.DES3_Mac(c_char_p(self.Mak), c_char_p(data[0:-8]), c_int(len(data)-8), mac)
		hexdump(mac.raw, 'MAC result')
		return mac.raw[0:8]

	def encrypt(self, data):
		if self.Pik is None:
			allkeys = mc.get(mckey)
			self.Pik, self.Mak = cPickle.loads(allkeys)
		buf = create_string_buffer(len(data))
		modCrypt.DES3_encrypt(c_char_p(data), c_char_p(self.Pik), buf, c_int(len(data)))
		return buf.raw

	def decrypt(self, data):
		if self.Pik is None:
			allkeys = mc.get(mckey)
			self.Pik, self.Mak = cPickle.loads(allkeys)
		buf = create_string_buffer(len(data))
		modCrypt.DES3_decrypt(c_char_p(data), c_char_p(self.Pik), buf, c_int(len(data)))
		return buf.raw

	def pwdGen(self, cardNo, pwd):
		pan = cardNo[-13:-1]
		pan = str2bcd(pan, 8)
		hexdump(pan, 'pan(bcd)')
		pin = str2bcd('06'+pwd, 4)
		pin = pin + '\xFF\xFF\xFF\xFF'
		hexdump(pin, 'pin(bcd)')
		xor = []
		#Xor
		i = 0
		while i < 8:
			xor.append(chr(ord(pan[i])^ord(pin[i])))
			i += 1
		outs = ''.join(xor)
		hexdump(outs, 'xor')
		return outs

class buildBase(object):
	def __init__(self, u, command):
		global SCOUNT
		SCOUNT += 1
		self.count = SCOUNT
		self.u = u
		self.command = command

	def decrypt(self, idx, data):
		global key
		if idx == 0:
			return data
		else:
			k = key[(idx-1)*8:idx*8]
#			print 'Decrypt Key:', k
			dlen, blen = 0, len(data)
			if blen % 8 > 0:
				dlen = (blen / 8 + 1) * 8
			else:
				dlen = blen
			p = create_string_buffer(dlen)
			k = c_char_p(k)

			gydes.DES_DEC(k, data, blen, p)
			return p.raw

	def encrypt(self, data):
		global ENCRYPT, key
		if ENCRYPT == False:
			self.idx = 0
			return data
		else:
			self.idx = random.randint(1, 10)
			k = key[(self.idx-1)*8:self.idx*8]
#			hexdump(k, 'keyidx=%d' % self.idx)

			dlen, blen = 0, len(data)
			if blen % 8 > 0:
				dlen = (blen / 8 + 1) * 8
			else:
				dlen = blen
			p = create_string_buffer(dlen)
			k = c_char_p(k)

			gydes.DES_ENC(k, data, blen, p)
#			hexdump(p.raw, 'Encrypted data')
			return p.raw

	def check(self, t):
#		t.assertEqual(self.h[0], self.idx)
		t.assertEqual(self.h[1], len(self.data)+PLAIN_BLOCK_SIZE)
		t.assertEqual(cut(self.h[2]), self.u[0])
		t.assertEqual(cut(self.h[3]), self.u[1])
		t.assertEqual(self.d[0], 0xaa)
		t.assertEqual(self.d[1], 0x55)
		t.assertEqual(self.d[2], self.command)
		t.assertEqual(self.d[3], self.count)
		t.assertEqual(cut(self.d[4]), VER)

class build1(buildBase):
	def __init__(self, u, **p):
		super(build1, self).__init__(u, 1)
		fmt = FMT_PLAINTEXT+'2B2H10s32s4I20s16s20s16s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s32s4I20s16s20s16s',0xaa,0x55,self.command,self.count,VER,'',p['bz'],p['je1'],p['bl'],p['je2'],u[2],u[3],'',u[4])
		data = self.encrypt(data)
		self.data = struct.pack(FMT_PLAINTEXT,self.idx,length,u[0],u[1]) + data

	def parse(self, data):
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		self.d = struct.unpack_from('!2B2H10s32s32s3I', self.data)

class build2(buildBase):
	def __init__(self, u, **p):
		super(build2, self).__init__(u, 2)
		fmt = FMT_PLAINTEXT+'2B2H10s32s4I20s16s20s16s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s32s4I20s16s20s16s',0xaa,0x55,self.command,self.count,VER,p['no'],0,0,0,0,u[2],u[3],'',u[4])
		data = self.encrypt(data)
		self.data = struct.pack(FMT_PLAINTEXT,self.idx,length,u[0],u[1]) + data

	def parse(self, data):
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		self.d = struct.unpack_from('!2B2H10s32s32sIiI', self.data)

class build3(buildBase):
	def __init__(self, u, **p):
		super(build3, self).__init__(u, 3)
		fmt = FMT_PLAINTEXT+'2B2H10s20s16s16s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s20s16s16s',0xaa,0x55,self.command,self.count,VER,u[2],u[3],u[4])
		data = self.encrypt(data)
		self.data = struct.pack(FMT_PLAINTEXT,self.idx,length,u[0],u[1]) + data

	def parse(self, data):
		fmt = '!2B2H10sI'
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		self.d = struct.unpack_from(fmt, self.data)

		self.p, count = [], self.d[5]
		data = self.data[struct.calcsize(fmt):]
		fmt = '!16s16s32s32s20s3IiI20s'
		for x in xrange(count):
			p = struct.unpack_from(fmt, data)
			self.p.append(p)
			data = data[struct.calcsize(fmt):]

class build4(buildBase):
	def __init__(self, u, **p):
		super(build4, self).__init__(u, 4)
		fmt = FMT_PLAINTEXT+'2B2H10s20s16s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s20s16s',0xaa,0x55,self.command,self.count,VER,u[2],u[4])
		data = self.encrypt(data)
		self.data = struct.pack(FMT_PLAINTEXT,self.idx,length,u[0],u[1]) + data

	def parse(self, data):
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		self.d = struct.unpack_from('!2B2H10sc', self.data)

class build5(buildBase):
	def __init__(self, u, **p):
		super(build5, self).__init__(u, 5)
		fmt = FMT_PLAINTEXT+'2B2H10s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s',0xaa,0x55,self.command,self.count,VER)
		self.data = struct.pack(FMT_PLAINTEXT,0,length,'','') + data

	def parse(self, data):
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		self.d = struct.unpack_from('!2B2H10s40s20s32s80s', self.data)

		data = self.data[struct.calcsize('!2B2H10s40s20s32s80s'):]
		self.p = data.split('|')

class build6(buildBase):
	def __init__(self, u, **p):
		super(build6, self).__init__(u, 6)
		fmt = FMT_PLAINTEXT+'2B2H10s32s16s'
		length = struct.calcsize(fmt)
		data = struct.pack('!2B2H10s32s16s',0xaa,0x55,self.command,self.count,VER,p['no'],u[3])
		data = self.encrypt(data)
		self.data = struct.pack(FMT_PLAINTEXT,self.idx,length,u[0],u[1]) + data

	def parse(self, data):
		self.h = struct.unpack_from(FMT_PLAINTEXT, data)
		self.data = self.decrypt(self.h[0], data[PLAIN_BLOCK_SIZE:])
		if len(self.data) >= struct.calcsize('!2B2H10s16s16s32s32s20s3IiI20s'):
			self.d = struct.unpack_from('!2B2H10s16s16s32s32s20s3IiI20s', self.data)
		else:
			self.d = struct.unpack_from('!2B2H10s', self.data)

class build7:
	def __init__(self):
		SCOUNT += 1
		fmt = FMT_PLAINTEXT+'2B2H10s'
		length = struct.calcsize(fmt)
		self.data = struct.pack(fmt, 0, length, '01001010000', '03', 0xaa, 0x55, 7, SCOUNT, VER)

	def parse(self, data):
		fmt = FMT_PLAINTEXT+'2B2H10sI'
		d = struct.unpack_from(fmt, data)
		count = d[9]
		print 'Order Number:', count
		d = data[struct.calcsize(fmt):]
		fmt = '!32s32s'
		for x in xrange(count):
			p = struct.unpack_from(fmt, d)
			d = d[struct.calcsize(fmt):]
			print 'No.%03d:' % (x+1,),
			print '%32s%32s' % (cut(p[0]), cut(p[1]))

class b8583_9(buildBase):
	'''签到
	'''
	def __init__(self, u, **p):
		super(b8583_9, self).__init__(u, 9)
		iso = GY8583()
		iso.setMTI('0800')
		iso.setBit(11, '000330')
		iso.setBit(41, PosNo)
		iso.setBit(42, EntNo)
		iso.addBit(60, (('N', 2, '00'), ('N', 6, '000085'), ('N', 3, '003')))
		iso.endBit(60)
		iso.addBit(63, (('N', 3, '01'),))
		iso.endBit(63)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		#解析密钥
		if iso.getBit(39) == '00':
			o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6), ('N', 3)))
			print d
			gydes = crypto_gydes()
			gydes.parseKeys(iso.getBit(62))

class b8583_10(buildBase):
	'''签退
	'''
	def __init__(self, u, **p):
		super(b8583_10, self).__init__(u, 10)
		iso = GY8583()
		iso.setMTI('0820')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(41, u[1])
		iso.setBit(42, u[0])
		iso.addBit(60, (('N', 2, '0'), ('N', 6, '1'), ('N', 3, '002')))
		iso.endBit(60)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6), ('N', 3)))
		print d

class b8583_12(buildBase):
	'''积分冲正
	'''
	def __init__(self, u, **p):
		super(b8583_12, self).__init__(u, 12)
		iso = GY8583()
		iso.setMTI('0400')
		iso.setBit(3, '210000')
		iso.setBit(4, '16728')
		iso.setBit(11, str(SCOUNT))
		#iso.setBit(22, '022', align='left')
		iso.setBit(25, '00')
		#iso.setBit(35, '0100101000111560001')
		iso.setBit(39, '98')
		iso.setBit(41, u[1])
		iso.setBit(42, u[0])
		iso.addBit(60, (('N', 2, '0'), ('N', 6, '1')))
		iso.endBit(60)
		iso.addBit(63, (('AN', 3, '38'), ))
		iso.endBit(63)
		iso.setBit(64, 'ABBA1223')
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print d

class b8583_13(buildBase):
	'''撤单冲正
	'''
	def __init__(self, u, **p):
		super(b8583_13, self).__init__(u, 13)
		iso = GY8583()
		iso.setMTI('0400')
		iso.setBit(3, '210000')
		iso.setBit(4, '16728')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(22, '022', align='left')
		iso.setBit(25, '00')
		iso.setBit(35, '0100101000111560001')
		iso.setBit(39, '98')
		iso.setBit(41, u[1])
		iso.setBit(42, u[0])
		iso.addBit(60, (('N', 2, '0'), ('N', 6, '1')))
		iso.endBit(60)
		iso.addBit(61, (('N', 2, '1'), ('N', 6, '11')))
		iso.endBit(61)
		iso.addBit(63, (('AN', 3, '38'), ))
		iso.endBit(63)
		iso.setBit(64, '00000000')
		gydes = crypto_gydes()
		data = iso.getRawIso()
		if not gydes.getKeys():
			print 'key:', mckey
			self.req = data
		else:
			print 'generate mac'
			mac = gydes.getMac(data)
			iso.setBit(64, mac)
			self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print d

class b8583_2(buildBase):
	'''积分撤单
	'''
	def __init__(self, u, **p):
		super(b8583_2, self).__init__(u, 2)
		iso = GY8583()
		iso.setMTI('0900')
		iso.setBit(3, '200000')
		iso.setBit(11, '000469')
		iso.setBit(22, '022', align='left')
		iso.setBit(25, '00')
		iso.setBit(35, '01001010001131530001')
		iso.setBit(37, '130522161019')
		iso.setBit(41, PosNo)
		iso.setBit(42, EntNo)
		iso.setBit(53, '0600000000000000')
		iso.addBit(60, (('N', 2, '62'),('N', 6, '000092'),('N', 6, '000001')))
		iso.endBit(60)
		iso.addBit(63, (('AN', 3, '001'), ))
		iso.endBit(63)
		iso.setBit(64, '00000000')
		gydes = crypto_gydes()
		data = iso.getRawIso()
		if not gydes.getKeys():
			print 'key:', mckey
			self.req = data
		else:
			print 'generate mac'
			mac = gydes.getMac(data)
			iso.setBit(64, mac)
			self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print d

class b8583_3(buildBase):
	'''查询当日积分明细
	'''
	def __init__(self, u, **p):
		super(b8583_3, self).__init__(u, 3)
		gydes = crypto_gydes()
		iso = GY8583()
		iso.setMTI('0920')
		iso.setBit(3, '700000')
		iso.setBit(11, '000068')
		iso.setBit(22, '021', align='left')
		iso.setBit(25, '00')
		iso.setBit(26, '06')
		iso.setBit(35, '01001010001d15600001')
		iso.setBit(41, PosNo)
		iso.setBit(42, EntNo)
		iso.setBit(52, '\xa0\x74\x9a\x5e\xc7\x70\xd5\xf4')
		iso.setBit(53, '2600000000000000')
		iso.addBit(60, (('N', 2, '22'), ('N', 6, '000114'),('N', 6, '000001')))
		iso.endBit(60)
		iso.addBit(63, (('AN', 3, '001'), ))
		iso.endBit(63)
		iso.setBit(64, '00000000')
		data = iso.getRawIso()
		if not gydes.getKeys():
			print 'key:', mckey
			self.req = data
		else:
			print 'generate mac'
			mac = gydes.getMac(data)
			iso.setBit(64, mac)
			self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print '>>>>> 60:', d
		o, d = iso.getBitNext(48, 0, (('N', 11), ('N', 2)))
		print '>>>>> 48:', d
		for x in xrange(int(d[1])):
			o, d = iso.getBitNext(48, o, (('N', 4), ('N', 6), ('N', 6), ('N', 6), ('ANS', 12), ('N', 2), ('N', 8), ('N', 12), ('N', 4), ('N', 12), ('N', 3), ('N', 12), ('N', 6)))
			print d

class b8583_6(buildBase):
	'''查询单笔明细
	'''
	def __init__(self, u, **p):
		super(b8583_6, self).__init__(u, 6)
		iso = GY8583()
		iso.setMTI('0920')
		iso.setBit(3, '710000')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(37, '130403151041')
		iso.setBit(41, '03')
		iso.setBit(42, '01001010000')
		iso.setBit(53, '0600000000000000')
		iso.addBit(60, (('N', 2, '62'), ('N', 6, '000300')))
		iso.endBit(60)
		iso.addBit(61, (('N', 6, '000300'), ('N', 6, '26')))
		iso.endBit(61)
		iso.addBit(63, (('AN', 3, '38'), ))
		iso.endBit(63)
		iso.setBit(64, '00000000')
		gydes = crypto_gydes()
		data = iso.getRawIso()
		if not gydes.getKeys():
			print 'key:', mckey
			self.req = data
		else:
			print 'generate mac'
			mac = gydes.getMac(data)
			iso.setBit(64, mac)
			self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print d
		#卡号n19，交易类型n4，交易处理码n6，POS机交易流水号n6，交易时间n6，POS中心参考号ans12，
		#应答标志n2，终端编号ans8，积分比例n4，积分金额n12，操作员编号n3，本次积分数n12，交易批次号n6
		o, d = iso.getBitNext(48, 0, (('N', 19), ('N', 4), ('N', 6), ('N', 6), ('N', 6), ('ANS', 12), ('N', 2), ('N', 8), ('N', 12), ('N', 4), ('N', 12), ('N', 3), ('N', 12), ('N', 6)))
		print d

class b8583_1(buildBase):
	'''积分
	'''
	def __init__(self, u, **p):
		super(b8583_1, self).__init__(u, 1)
		iso = GY8583()
		iso.setMTI('0900')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(3, '210000')
		iso.setBit(4, '167280')
		iso.setBit(22, '022', align='left')
		iso.setBit(25, '00')
		iso.setBit(35, '0100101000111560001')
		iso.setBit(41, PosNo)
		iso.setBit(42, EntNo)
		iso.addBit(48, (('N', 4, '800'), ('N', 12, '57550')))
		iso.endBit(48)
		iso.setBit(49, '156')
		iso.setBit(53, '0600000000000000')
		iso.addBit(60, (('N', 2, '61'), ('N', 6, '000300')))
		iso.endBit(60)
		iso.addBit(63, (('AN', 3, u[3]), ))
		iso.endBit(63)
		iso.setBit(64, '00000000')
		gydes = crypto_gydes()
		data = iso.getRawIso()
		if not gydes.getKeys():
			print 'key:', mckey
			self.req = data
		else:
			print 'generate mac'
			mac = gydes.getMac(data)
			iso.setBit(64, mac)
			self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6)))
		print d
		o, d = iso.getBitNext(63, 0, (('AN', 3),))
		print d

class b8583_14(buildBase):
	'''同步参数
	'''
	def __init__(self, u, **p):
		super(b8583_14, self).__init__(u, 14)
		iso = GY8583()
		iso.setMTI('0950')
		iso.setBit(3, '720000')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(41, '03')
		iso.setBit(42, '000001001010000')
		iso.addBit(62, (('N', 4, '0'), ('N', 4, '0001'), ('N', 4, '1')))
		iso.endBit(62)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		ans39 = iso.getBit(39)
		if ans39 != '00':
			o, d = iso.getBitNext(62, 0, (('AN', 512),))
			print d
		else:
			o, d = iso.getBitNext(62, 0, (('N', 4), ('ANS', 40), ('ANS', 25), ('ANS', 30), ('N', 4)))
			print 'money:'
			print '(%s)' % d[4]
			if int(d[4]) != 1:
				for x in xrange(6):	#货币代码个数
					o, d = iso.getBitNext(62, o, (('N', 2), ('N', 3), ('ANS', 10)))
					print d
			else:
				print 'no update'
			o, d = iso.getBitNext(62, o, (('N', 4), ('N', 2)))
			print 'country:'
			print d
			d = int(d[1])
			i = 0
			if d != 0:
				for x in xrange(d):
					o, d = iso.getBitNext(62, o, (('N', 3), ('N', 3), ('N', 1)))
					i+=1
					print d


class b8583_15(buildBase):
	'''上传参数
	'''
	def __init__(self, u, **p):
		super(b8583_15, self).__init__(u, 15)
		iso = GY8583()
		iso.setMTI('0950')
		iso.setBit(3,  '730000')
		iso.setBit(11, '000004')
		iso.setBit(41, '000003')
		iso.setBit(42, '000001001010000')
		iso.addBit(48, (('N', 2, '5'), ('N', 4, '1234'), ('N', 4, '0000'), ('N', 4, '0000'), ('N', 4, '0000'), ('N', 4, '0000')))
		iso.endBit(48)
		iso.addBit(63, (('N', 3, '001'),))
		iso.endBit(63)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()

class b8583_16(buildBase):
	'''批上送
	'''
	def __init__(self, u, **p):
		super(b8583_16, self).__init__(u, 16)
		iso = GY8583()
		iso.setMTI('0320')
		iso.setBit(11, '000682')
		iso.setBit(41, '03')
		iso.setBit(42, '01001010000')
		iso.addBit(60, (('N', 2, '00'), ('N', 6, '000112'), ('N', 3, '201')))
		iso.endBit(60)
		iso.addBit(48, (('N', 2, '0'), ('N', 2, '1')))
		iso.addBit(48, (('N', 6, '000675'), ('N', 20, '00000000001001010001'), ('N', 12, '000000015585'), ('N', 4, '0001'), ('N', 12, '000000000002'), ('N', 12, '000000000001')))
#		iso.addBit(48, (('N', 6, '001001'), ('N', 20, '01001010002'), ('N', 12, '124'), ('N', 4, '1200'), ('N', 12, '20000'), ('N', 12, '2400')))
#		iso.addBit(48, (('N', 6, '002001'), ('N', 20, '01001010003'), ('N', 12, '125'), ('N', 4, '2000'), ('N', 12, '30000'), ('N', 12, '6000')))
		iso.endBit(48)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6), ('N', 3)))
		print d

class b8583_17(buildBase):
	'''批上送结束
	'''
	def __init__(self, u, **p):
		super(b8583_17, self).__init__(u, 17)
		iso = GY8583()
		iso.setMTI('0320')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(41, '03')
		iso.setBit(42, '01001010000')
		iso.addBit(60, (('N', 2, '61'), ('N', 6, '000084'), ('N', 3, '202')))
		iso.endBit(60)
		iso.addBit(48, (('N', 4, '3'), ))
		iso.endBit(48)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6), ('N', 3)))
		print d

class b8583_11(buildBase):
	'''批结算
	'''
	def __init__(self, u, **p):
		super(b8583_11, self).__init__(u, 11)
		iso = GY8583()
		iso.setMTI('0500')
		iso.setBit(11, str(SCOUNT))
		iso.setBit(41, '03')
		iso.setBit(42, '01888740000')
		iso.setBit(49, '156')
		iso.addBit(60, (('N', 2, '61'), ('N', 6, '000300'), ('N', 3, '201')))
		iso.endBit(60)
		iso.addBit(63, (('AN', 3, '012'), ))
		iso.endBit(63)
		iso.addBit(48, (('N', 12, '0'), ('N', 3, '0'), ('N', 12, '0'), ('N', 3, '0'), ('N', 12, '100087'), ('N', 3, '10'), ('N', 12, '300'), ('N', 3, '2'), ('N', 1, '0')))
		iso.endBit(48)
		self.req = iso.getRawIso()

	def parse(self, data):
		iso = GY8583(data)
		iso.showIsoBits()
		o, d = iso.getBitNext(60, 0, (('N', 2), ('N', 6), ('N', 3)))
		print d

####################################################################################################

def recv(sock, length):
	data = ''
	while 1:
		partial_data = ''
		try:
			partial_data = sock.recv(length - len(data))
		except:
			return None

		if len(partial_data) == 0:
			return None

		data += partial_data
		if len(data) == length:
			return data

class testcase:
	fail_conn, fail_comm = 0, 0			#连接失败/业务失败次数

	def __init__(self):
		self.business = random.choice([1,3,5])
		self.obj, self.serial = None, None

	def doComplex(self):
		self.sock = socket.socket()
		try:
			self.sock.connect(SERVER)
		except:
			self.fail_conn += 1
			self.sock = None
		else:
			if self.business == 1:
				self.unit = (getEntNo(), '03', getCardNo(), '42', '')
				self.obj = build1(self.unit, bz=156, bl=1000, je1=600, je2=60)
			elif self.business == 2:
				self.obj = build2(self.unit, no=self.serial)
			elif self.business == 3:
				self.unit = (getEntNo(), '03', getCardNo(), '42', '')
				self.obj = build3(self.unit)
			elif self.business == 5:
				self.unit = (getEntNo(), '03', getCardNo(), '42', '')
				self.obj = build5(self.unit)
			elif self.business == 6:
#				print self.serial
				try:
					self.obj = build6(self.unit, no=self.serial)
				except:
#					self.fail_comm += 1
					self.sock.close()
					return

			self.sock.send(self.obj.data)
			data = recv(self.sock, PLAIN_BLOCK_SIZE)
			if data is None:
				self.fail_comm += 1
				self.sock.close()
				return
			d = struct.unpack(FMT_PLAINTEXT, data)
			length = d[1] - PLAIN_BLOCK_SIZE
			encryptedBlock = recv(self.sock, length)
			if encryptedBlock is None:
				self.fail_comm += 1
				self.sock.close()
				return
			self.data = ''.join([data, encryptedBlock])

			#关闭连接
			self.sock.close()
			self.sock = None

			#准备下一个包
			self.obj.parse(self.data)
			if self.business == 1:
				self.serial = cut(self.obj.d[5])
				self.business = 2
			else:
				self.business = random.choice([1,1,1,1,1,1,1,1,1,1,3,3,3,5,6,6,6,6])

	def run(self, times):
		self.alltime = timeit.Timer(self.doComplex).timeit(times)

class Test8583(unittest.TestCase):
	def setUp(self):
		self.sock = socket.socket()
		self.sock.connect(SERVER)

	def tearDown(self):
		self.sock.close()
		self.sock = None

	def addHead(self, d):
		return ''.join([struct.pack('!H', 11 + len(d)), '\x60\x85\x83\x85\x83\x64\x31\x00\x60\x00\x01', d])

	def test09(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_9(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.9.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.9.recv')
		obj.parse(d)
	'''
	def test10(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_10(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.10.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.10.recv')
		obj.parse(d)

	def test1(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_1(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.1.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.1.recv')
		obj.parse(d)

	def test2(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_2(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.2.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.2.recv')
		obj.parse(d)

	def test3(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_3(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.3.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.3.recv')
		obj.parse(d)

	def test6(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_6(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.6.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.6.recv')
		obj.parse(d)

	def test14(self):
		unit = ('01001010000', '03', getCardNo(), '42', '')
		obj = b8583_14(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.14.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.14.recv')
		obj.parse(d)

	def test15(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_15(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.15.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.15.recv')
		obj.parse(d)

	def test11(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_11(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.11.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.11.recv')
		obj.parse(d)

	def test16(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_16(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.16.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.16.recv')
		obj.parse(d)

	def test17(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_17(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.17.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.17.recv')
		obj.parse(d)

	def test12(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_12(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.12.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.12.recv')
		obj.parse(d)

	def test13(self):
		unit = (getEntNo(), '03', getCardNo(), '42', '')
		obj = b8583_13(unit)
		d = self.addHead(obj.req)
		hexdump(d, '8583.13.send')
		self.sock.send(d)

		d = recv(self.sock, 2)
		l = struct.unpack('!H', d)[0]
		d = recv(self.sock, l)[11:]
		hexdump(d, '8583.13.recv')
		obj.parse(d)
	'''
#class TestGyMidder(unittest.TestCase):
#	def setUp(self):
#		self.sock = socket.socket()
#		self.sock.connect(SERVER)
#
#	def tearDown(self):
#		self.sock.close()
#		self.sock = None
#
#	def test1(self):
#		unit = (getEntNo(), '03', getCardNo(), '42', '')
#		obj = build1(unit, bz=156, bl=1000, je1=600, je2=60)
#		self.sock.send(obj.data)
#
#		data = recv(self.sock, PLAIN_BLOCK_SIZE)
#		d = struct.unpack(FMT_PLAINTEXT, data)
#		length = d[1] - PLAIN_BLOCK_SIZE
#		encryptedBlock = recv(self.sock, length)
#		data = data + encryptedBlock
#
#		obj.parse(data)
#
#		obj.check(self)
#		self.assertEqual(cut(obj.d[6]), '')
#		self.assertEqual(obj.d[7], 0)
#		self.assertTrue(len(obj.d[5]) > 0)
#		self.assertTrue(obj.d[8] > 0)
#		self.assertTrue(obj.d[9] >= obj.d[8])
#
#		global PVSERIAL, PVUNIT
#		PVSERIAL = cut(obj.d[5])
#		PVUNIT = unit
#
##		print '>>> PV:', cut(obj.d[5]), obj.d[7], obj.d[8]
#
#	def test2(self):
#		obj = build2(PVUNIT, no=PVSERIAL)
#		self.sock.send(obj.data)
#
#		data = recv(self.sock, PLAIN_BLOCK_SIZE)
#		d = struct.unpack(FMT_PLAINTEXT, data)
#		length = d[1] - PLAIN_BLOCK_SIZE
#		encryptedBlock = recv(self.sock, length)
#		data = data + encryptedBlock
#
#		obj.parse(data)
#		obj.check(self)
#
#		zclsh, cdlsh = cut(obj.d[5]), cut(obj.d[6])
#
#		self.assertNotEqual(zclsh, cdlsh)
#		self.assertEqual(obj.d[7], 0)
#		self.assertTrue(zclsh > 0)
#		self.assertTrue(cdlsh > 0)
#		self.assertTrue(obj.d[8] < 0)
#		self.assertTrue(obj.d[9] >= 0)
#
##		print 'Cancel success! bcjf=%.2f, jfye=%.2f' % (obj.d[8]/100.0, obj.d[9]/100.0)
#
#	def test3(self):
#		unit = (getEntNo(), '03', getCardNo(), '42', '')
#		obj = build3(unit)
#		self.sock.send(obj.data)
#
#		data = recv(self.sock, PLAIN_BLOCK_SIZE)
#		d = struct.unpack(FMT_PLAINTEXT, data)
#		length = d[1] - PLAIN_BLOCK_SIZE
#		encryptedBlock = recv(self.sock, length)
#		data = data + encryptedBlock
#
#		obj.parse(data)
#		obj.check(self)
#
#		self.assertTrue(obj.d[5] >= 0)
##		for x in xrange(obj.d[5]):
##			print 'No.%03d' % (x+1,),
##			x = obj.p[x]
##
##			cancelNo = cut(x[3])
##			if len(cancelNo) == 0:
##				print 'PV:', cut(x[2]),
##			else:
##				print 'CA:', cancelNo,
##			print '%8.2f%7.4f%8.2f%11.2f%22s' % (x[4]/100.0, x[5]/10000.0, x[7]/100.0, x[8]/100.0, cut(x[9]))
#
##	def test4(self):
##		unit = (getEntNo(), '03', getCardNo(), '42', '')
##		obj = build4(unit, pwd='111111')
##		self.sock.send(obj.data)
##
##		data = recv(self.sock, PLAIN_BLOCK_SIZE)
##		d = struct.unpack(FMT_PLAINTEXT, data)
##		length = d[1] - PLAIN_BLOCK_SIZE
##		encryptedBlock = recv(self.sock, length)
##		data = data + encryptedBlock
##
##		obj.parse(data)
##		obj.check(self)
##
##		self.assertEqual(ord(obj.d[5]), 0)
#
#	def test5(self):
#		unit = (getEntNo(), '03', getCardNo(), '42', '')
#		obj = build5(unit)
#		self.sock.send(obj.data)
#
#		data = recv(self.sock, PLAIN_BLOCK_SIZE)
#		d = struct.unpack(FMT_PLAINTEXT, data)
#		length = d[1] - PLAIN_BLOCK_SIZE
#		encryptedBlock = recv(self.sock, length)
#		data = data + encryptedBlock
#
#		obj.parse(data)
#
#		self.assertEqual(obj.h[1], len(obj.data)+PLAIN_BLOCK_SIZE)
#		self.assertEqual(obj.d[0], 0xaa)
#		self.assertEqual(obj.d[1], 0x55)
#		self.assertEqual(obj.d[2], obj.command)
#		self.assertEqual(obj.d[3], obj.count)
#		self.assertEqual(cut(obj.d[4]), VER)
#
#		self.assertEqual(cut(obj.d[5]), 'www.gy.com')
#		self.assertEqual(cut(obj.d[6]), '(086)0755-88888888')
#		self.assertTrue(len(cut(obj.d[7])) > 0)
#
#	def test6(self):
#		obj = build6(PVUNIT, no=PVSERIAL)
#		self.sock.send(obj.data)
#
#		data = recv(self.sock, PLAIN_BLOCK_SIZE)
#		d = struct.unpack(FMT_PLAINTEXT, data)
#		length = d[1] - PLAIN_BLOCK_SIZE
#		encryptedBlock = recv(self.sock, length)
#		data = data + encryptedBlock
#
#		obj.parse(data)
#		obj.check(self)
#
#		self.assertTrue(len(cut(obj.d[6])) > 0)
#		tradeNo, cancelNo = cut(obj.d[7]), cut(obj.d[8])
#
#		if len(cancelNo) == 0:
#			self.assertTrue(cut(obj.d[7]) > 0)
#			self.assertTrue(obj.d[9] > 0)
#			self.assertTrue(obj.d[10] > 0)
#			self.assertTrue(obj.d[13] > 0)
#			self.assertTrue(obj.d[14] > 0)
#			self.assertEqual(obj.d[12], 0)
#
##			print 'PV:', cut(obj.d[7]),
#		else:
#			self.assertEqual(obj.d[9], 0)
#			self.assertEqual(obj.d[10], 0)
#			self.assertEqual(obj.d[11], 0)
#			self.assertTrue(obj.d[13] < 0)
#			self.assertTrue(obj.d[14] >= 0)

#			print 'CA:', cancelNo,

#		print '%8.2f%7.4f%8.2f%11.2f%22s' % (obj.d[9]/100.0, obj.d[10]/10000.0, obj.d[12]/100.0, obj.d[13]/100.0, cut(obj.d[14]))

def unit():
	try:
		unittest.main()
	except SystemExit:
		pass

def stress_unit(times):
	u = testcase()
	u.run(times)
	print '%d test, Time: %f, Connnect: %d, Business: %d' % (times, u.alltime, u.fail_conn, u.fail_comm)

def pressure1():
	jobs = [Process(target = unit) for _ in xrange(1)]
	for x in jobs:
		x.start()
	for x in jobs:
		x.join()

def pressure2(count, times):
	#开启count个进程，每个进程执行times次请求
	jobs = [Process(target = stress_unit, args = (times,)) for _ in xrange(count)]
	for x in jobs:
		x.start()
	for x in jobs:
		x.join()

if __name__ == '__main__':
	#
	data = '\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x12\x34\x56\x78\x90\x00\x00\x00\x00\x00\x00\x00\x00'
	gd = crypto_gydes()
	gd.Mak = '\x00\x01\x02\x03\x04\x05\x06\x07'
	hexdump(data, 'data')
	hexdump(gd.Mak, 'mak')
	hexdump(gd.getMac(data), 'mac')

	random.seed()
	fillEntNo()
	for x in xrange(80):
		key += chr(x+1)
	pressure1()

#	pressure2(2, 100)
