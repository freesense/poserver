#!/usr/bin/python2.6
#coding: utf-8

import cx_Oracle, random
from multiprocessing import JoinableQueue, Process
from threading import Thread
from ctypes import *

PROCESSOR_COUNT = 8
keysample = [chr(x) for x in xrange(256)]
key = c_char_p('0123456789abcdef')
q = JoinableQueue()
dll = CDLL('../gydes.so')
sql = '''
INSERT INTO T_GY_POS_PMK (GY_POS_PMK_ID,
      GY_POS_NO,
      GY_POS_PMK,
      GY_CREATE_DATE,
      GY_CREATE_MAN,
      GY_UPDATE_DATE,
      GY_UPDATE_MAN,
      GY_SUB_CENTER,
      GY_POS_PMK_INFO)
   VALUES (SEQ_T_GY_POS_PMK.NEXTVAL,
      :1,
      :2,
      SYSDATE,
      0,
      SYSDATE,
      0,
      '01',
      :3)
'''

def gen_pmk():
	pmk = ''.join([random.choice(keysample) for i in xrange(16)])
	buf = create_string_buffer(16)
	dll.DES3_encrypt(c_char_p(pmk), key, buf, c_int(16))
	return pmk, buf.raw

def worker():
	conn = cx_Oracle.Connection(user='testcd_pmk', password='111111', dsn='192.168.1.115:1521/orcl')#, threaded=True)
	c = conn.cursor()
	pmk, enc = c.var(cx_Oracle.BLOB), c.var(cx_Oracle.BLOB)

	while 1:
		params = []
		x = q.get()
		for m in xrange(50):	#托管企业
			posno = '%s%02d000001' % (x, m+1)
			_pmk, _enc = gen_pmk()
			enc.setvalue(0, _enc)
			pmk.setvalue(0, _pmk)
			c.execute(sql, [posno, enc, pmk])
		for m in xrange(2500):	#托管企业
			posno = '%s00%04d01' % (x, m+1)
			_pmk, _enc = gen_pmk()
			enc.setvalue(0, _enc)
			pmk.setvalue(0, _pmk)
			c.execute(sql, [posno, enc, pmk])
		conn.commit()
		print 'EntNo: %s000000, OK.' % x
		q.task_done()

def main():
	random.seed()
	for x in ['01%03d' % (x+1) for x in xrange(999)]:
		q.put(x)

	for x in xrange((PROCESSOR_COUNT << 1) - 1):
		p = Process(target=worker)
		p.daemon = True
		p.start()

	q.join()

if __name__ == '__main__':
	main()
