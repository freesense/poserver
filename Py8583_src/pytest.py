#!/usr/bin/python2.6
#coding:utf8

from Py8583 import *
import time

s3 = '\x08\x20\x00\x20\x00\x00\x00\xc0\x00\x10\x00\x18\x90\x30\x30\x30\x30\x30\x30\x30\x31\x30\x30\x30\x30\x30\x31\x34\x30\x31\x30\x32\x30\x30\x30\x30\x00\x11\x00\x00\x00\x01\x00\x20'

def hexdump(data, text = 'Hexdump'):
	'''16进制输出，向logging模块输出
	data - 要输出的数据
	text - 输出标题
	lv - 输出级别
	'''
	if data is None:
		print '%s, None' % text
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
	print outs

def basic_test():
	print dir(Py8583)

	print '>>> bcd2dec'
	s='\x13\x44\x90\x02'
	print bcd2dec(s)
	print '>>> bcd2str'
	s='\x13\xfa\x8b'
	print bcd2str(s)
	print bcd2str(s, 10, 'left')
	print bcd2str(s, 10, 'right')
	print '>>> dec2bcd'
	hexdump(dec2bcd(1096), "dec2bcd(1096)")
	hexdump(dec2bcd(1096, 10, 'left'), "dec2bcd(1096, 10, 'left')")
	hexdump(dec2bcd(1096, 10, 'right'), "dec2bcd(1096, 10, 'right')")
	hexdump(dec2bcd(109), "dec2bcd(109)")
	hexdump(dec2bcd(109, 6, 'right'), "dec2bcd(109, 6, 'right')")
	hexdump(dec2bcd(109, 6, 'left'), "dec2bcd(109, 6, 'left')")
	print '>>> str2bcd'
	hexdump(str2bcd('a5700f9'), "str2bcd('a5700f9')")
	hexdump(str2bcd('3f9a', 2, 'left'), "str2bcd('3f9a', 2, 'left')")
	hexdump(str2bcd('8b4c6603', 4, 'left'), "str2bcd('8b4c6603', 4, 'left')")
	hexdump(str2bcd('b4c6603', 4, 'left'), "str2bcd('b4c6603', 4, 'left')")
	hexdump(str2bcd('b4c6603', 4, 'right'), "str2bcd('b4c6603', 4, 'right')")
	hexdump(str2bcd('b4c66', 9, 'left'), "str2bcd('b4c66', 9, 'left')")
	hexdump(str2bcd('b4c66', 9, 'right'), "str2bcd('b4c66', 9, 'right')")

	s = '\x09\x30\x20\x20\x00\x01\x0a\xc1\x00\x11\x71\x00\x01\x00\x15\x16\x08\x01\x00\x10\x10\x30\x32\x31\x33\x37\x32\x39\x32\x36\x37\x34\x34\x30\x30\x30\x30\x30\x30\x30\x30\x30\x32\x30\x30\x30\x30\x30\x32\x30\x30\x36\x30\x31\x30\x30\x30\x30\x01\x04\x01\x00\x10\x10\x00\x10\x06\x12\x10\x00\x00\x01\x51\x31\x63\x14\x90\x21\x37\x29\x26\x74\x40\x00\x00\x00\x00\x20\x00\x00\x08\x88\x88\x80\x30\x00\x00\x00\x00\x26\x66\x70\x02\x00\x00\x00\x01\x33\x33\x00\x00\x01\x00\x08\x03\x00\x00\x01\x34\x30\x35\x38\x45\x34\x37\x45'
	obj = Py8583()
	print obj.parse(s)
	print obj.mti
	print str(obj)
	#print obj.getBit(22)
	#print obj.getBit(39)
	p, d = obj.getBitNext(48, 0, ('N', 11))
	print d
	p, d = obj.getBitNext(48, p, ('N', 4))
	print d
	p, d = obj.getBitNext(48, p, ('N', 6))
	print d
	p, d = obj.getBitNext(48, p, ('N', 6))
	print d
	p, d = obj.getBitNext(48, p, ('N', 6))
	print d
	p, d = obj.getBitNext(48, p, ('ANS', 12))
	print d
	p, d = obj.getBitNext(48, p, ('N', 2))
	print d
	p, d = obj.getBitNext(48, p, ('ANS', 8))
	print d
	p, d = obj.getBitNext(48, p, ('N', 12))
	print d
	p, d = obj.getBitNext(48, p, ('N', 4))
	print d
	p, d = obj.getBitNext(48, p, ('N', 12))
	print d
	p, d = obj.getBitNext(48, p, ('N', 3))
	print d
	p, d = obj.getBitNext(48, p, ('N', 12))
	print d
	p, d = obj.getBitNext(48, p, ('N', 6))
	print d

	iso = repr(obj)
	hexdump(s)
	hexdump(iso)
	print s == iso

	obj = Py8583()
	obj.mti = 900
	obj.setBit(3, "210000")
	obj.setBit(4, "147")
	obj.setBit(11, "000126")
	obj.setBit(22, "022")
	obj.setBit(25, "00")
	obj.setBit(35, "01001010001D15300001")
	obj.setBit(41, "029")
	obj.setBit(49, "156")
	obj.setBit(42, "01001010000")
	obj.setBit(64, "000000")
	obj.addBit(48, ("N", 4, "0100"))
	obj.addBit(48, ("N", 12, "50000"))
	obj.addBit(60, ("N", 2, "61"))
	obj.addBit(60, ("N", 6, "100301"))
	obj.addBit(60, ("N", 6, "011400"))
	obj.addBit(63, ("N", 3, "190"))
	print str(obj)
	iso = obj.getRawIso()
	hexdump(iso, '900打包')

def parse_test():
	obj = Py8583()
	obj.parse(s3)
	print str(obj)

	offset, _ = obj.getBitNext(60, 0, ('N', 2))
	print _
	offset, s2 = obj.getBitNext(60, offset, ('N', 6))
	print s2
	offset, _ = obj.getBitNext(60, offset, ('N', 3))
	print _

def build_test():
	obj = Py8583()
	obj.mti = 910
#	obj.setBit(3, "210000")
#	obj.setBit(4, "000000000147")
#	obj.setBit(11, "000126")
#	obj.setBit(22, "022")
#	obj.setBit(25, "00")
#	obj.setBit(35, "01001010001D15300001")
#	obj.setBit(41, "029")
#	obj.setBit(42, "01001010000")
#	obj.addBit(48, ("N", 4, "0100"))
#	obj.addBit(48, ("N", 12, "50000"))
#	obj.setBit(49, "156")
#	obj.addBit(60, ('N', 2, '00'))
#	obj.addBit(60, ('N', 6, '000001'))
#	obj.addBit(60, ('N', 3, '003'))
	obj.addBit(63, ("AN", 3, "GYT"))
	obj.addBit(63, ("LL", 2, "71"))
#	obj.setBit(64, "000000")
	x = obj.getRawIso()
	hexdump(x)

def test8583():
	basic_test()
	import timeit
	print timeit.repeat('parse_test()', 'from pytest import parse_test', repeat=1, number=1000000)
	print timeit.repeat('build_test()', 'from pytest import build_test', repeat=1, number=1000000)

def cb(conn):
	print 'callback', conn

def testTimer():
	timer_reg(3, cb, 333)
	while 1:
		time.sleep(1)

if __name__ == "__main__":
#	parse_test()
	basic_test()
