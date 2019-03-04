#!/usr/bin/python2.6
#coding: utf-8
'''POS机访问Oracle数据库模块
'''

import zmq, cx_Oracle, posp, os, logging, time, threading, struct, posp
from posp import cut
from gyconfig import *
from multiprocessing import Process

class dbVisitor(object):
	def __init__(self):
		self.conn, self.iError, self.reserveData = None, 0, None
		self.dInvoke = {
			'SignIn'			: self.doSignIn,			#签到
			'SignOff'			: self.doSignOff,			#签退

			'PV'				: self.doPV,				#积分
			'PV Next'			: self.doPV,
			'Cancel'			: self.doCancel,			#撤单
			'Cancel Next'		: self.doCancel,
			'PV Positive'		: self.doPositive,			#积分冲正
			'Cancel Positive'	: self.doPositive,			#撤单冲正

			'Query(s)'			: self.doQuerys,			#查询当日积分卡交易
			'Query'				: self.doQuery,				#查询流水号交易
			'Query Next'		: self.doQuery,

			'SynVars'			: self.doSyncVars,			#同步参数
			'UpdRates'			: self.doUpdateRates,		#上传参数

			'Orders'			: self.doQueryOrders,		#查询订单
			'Order Detail'		: self.doQueryOrderDetail,	#查询订单详情
			'Ent Info'			: self.doQueryEntInfo,		#查询企业详情
			'POS CFG'			: self.doPosConfiged,		#设置POS密钥烧入状态

			'BatchSettle'		: self.doBatchSettle,		#批结算
			'Batch Update'		: self.doBatchUpload,		#批上传
			'Batch Done'		: self.doBatchOK,			#批上传结束
		}

	def dispatch(self, conn, obj):
		func = self.dInvoke.get(obj.status, None)
		if func is not None:
			c, obj.sql, self.conn, self.reserveData, self.iError = conn.cursor(), 'invalid sql statement', conn, None, 0

			obj.timers.count()
			try:
				func(c, obj)
			except cx_Oracle.DatabaseError, e:
				obj.timers.count('db')
				err, = e.args

				if self.iError == 1:
					obj.status, obj.parser.ErrInfo = '9990', '数据库执行超时'
				elif err.code in [12154,12541,12543,12540,1014,1033,1034,1035,1089,1090,1092,3113,3114,3106]:
					posp.logger.exception('Reconnect ORACLE')
					self.reserveData = obj
				else:
					posp.logger.exception(obj.sql)
					obj.status, obj.parser.ErrInfo = '9998', '内部错误'

#			except cx_Oracle.OperationalError:
#				obj.timers.count('db')
#				if self.iError == 1:
#					obj.status, obj.parser.ErrInfo = '9990', '数据库执行超时'
#				else:
#					posp.logger.exception('OperationalError')
#					self.reserveData = obj
#			except:
#				obj.timers.count('db')
#				posp.logger.exception(obj.sql)
#				obj.status, obj.parser.ErrInfo = '9998', '内部错误'

			del obj.sql
			c.close()
			obj.timers.count('postdb')
		else:
			posp.logger.warning('Unable to deal with function: %s' % obj.status)
			obj.status, obj.parser.ErrInfo = '9999', '该业务不被支持'

	def buildSerialNo(self, obj):
		'''db_process使用，建立业务流水号，参数仅测试使用
		processid - 调用者PID
		extSerial - 调用进程维护的序列号，该序列号循环使用
		return - 新的流水号
		'''
		if obj.parser.serialno is None:
			obj.parser.serialno = obj.parser.PosNo + str(int(time.time()))

	def doPV(self, c, obj):
		posno, je, jfbl, jf = obj.parser.EntNo+obj.parser.PosNo, '%.2f' % (obj.parser.je/100.0), '%.4f' % (obj.parser.jfbl/10000.0), '%.2f' % (obj.parser.jf/100.0)
		retstr, _errInfo, bcjf, jfye = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.NUMBER)
		self.buildSerialNo(obj)
		obj.sql = 'P_GY_POINTS_DETAIL %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s' % (obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, je, jfbl, jf, str(obj.parser.currency), obj.parser.EntNo+obj.parser.serialno, obj.parser.orgBatch, obj.parser.orgSerial, posno, obj.parser.oper)
		obj.timers.count('predb')

		c.callproc('P_GY_POINTS_DETAIL', [obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, je, jfbl, jf, str(obj.parser.currency), obj.parser.EntNo+obj.parser.serialno, obj.parser.orgBatch, obj.parser.orgSerial, posno, obj.parser.oper, retstr, _errInfo, bcjf, jfye])

		obj.timers.count('db')
		obj.status, obj.parser.ErrInfo = retstr.getvalue(), _errInfo.getvalue()
		if obj.status == '0000':
			obj.parser.bcjf, obj.parser.jfye = int(round(bcjf.getvalue() * 100)), int(round(jfye.getvalue() * 100))
		elif obj.status == '0010':
			obj.status = 'PV Next'

	def doCancel(self, c, obj):
		posno, retstr, bcjf, jfye, _err, _jfje, _jfbl = obj.parser.EntNo+obj.parser.PosNo, c.var(cx_Oracle.STRING), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.STRING), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.NUMBER)
		self.buildSerialNo(obj)
		obj.sql = 'P_GY_POINTS_CANCEL %s, %s, %s, %s, %s, %s, %s, %s, %s' % (obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, obj.parser.EntNo+obj.parser.serialno, posno+obj.parser.waitcancelOrderNo, obj.parser.batch, obj.parser.PosSerial, posno, obj.parser.oper)
		obj.timers.count('predb')

		c.callproc('P_GY_POINTS_CANCEL', [obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, obj.parser.EntNo+obj.parser.serialno, obj.parser.EntNo+obj.parser.waitcancelOrderNo, obj.parser.batch, obj.parser.PosSerial, posno, obj.parser.oper, retstr, _err, bcjf, jfye, _jfje, _jfbl])

		obj.timers.count('db')
		obj.parser.ErrInfo, obj.status = _err.getvalue(), retstr.getvalue()
		if obj.status == '0000':
			bcjf, jfye = bcjf.getvalue(), jfye.getvalue()
			if bcjf is not None:
				obj.parser.bcjf = int(round(bcjf * (-100)))
			if jfye is not None:
				obj.parser.jfye = int(round(jfye * 100))
			obj.parser.jfje, obj.parser.jfbl = int(round(_jfje.getvalue() * -100)), int(round(_jfbl.getvalue() * 10000))
		elif obj.status == '0010':
			obj.status, obj.parser.bcjf, obj.parser.jfye = 'Cancel Next', int(round(bcjf.getvalue() * -100)), int(round(jfye.getvalue() * 100))

	def doQuerys(self, c, obj):
		_ret, _msg, _cur = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR)
		obj.sql = 'P_GY_CARD_TRANS_LOG_TD %s, %s, %s, %s' % (obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_CARD_TRANS_LOG_TD', [obj.parser.EntNo, obj.parser.CardNo, obj.parser.pwd, obj.parser.oper, _ret, _msg, _cur])

		obj.timers.count('db')
		_cur, obj.parser.body, obj.parser.count, obj.status, obj.parser.presDial = result[6], '', 0, _ret.getvalue(), []

		if obj.status == '0000':
			for r in _cur:
				obj.parser.count += 1
				ent = {'OPERATOR_NAME':r[0],'POS_NO':r[1],'TRANS_NO':r[2],'CANCEL_TRANS_NO':r[3],'BAT_NO':r[4],'TRADE_NO':r[5],'MONEY':r[6], 'PV_MONEY':r[7],'POINT_RATIO':r[8],'TRANS_FLAG':r[9],'POINT_THIS':r[10],'POINT_ALL':r[11],'TRANS_TIME':r[12],'CARD_NO':r[13]}
				obj.parser.presDial.append(ent)
			_cur.close()
			if obj.parser.count == 0:
				obj.parser.ErrInfo = '无交易数据'
		else:
			obj.parser.ErrInfo = _msg.getvalue()

	def doQuery(self, c, obj):
		_ret, errmsg, _cardno, _cur, obj.parser.detail = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR), []
		obj.sql = 'P_GY_CARD_TRANS_LOG_ID %s, %s' % (obj.parser.EntNo+obj.parser.orgSerial, obj.parser.EntNo)
		obj.timers.count('predb')

		result = c.callproc('P_GY_CARD_TRANS_LOG_ID', [obj.parser.EntNo+obj.parser.orgSerial, obj.parser.EntNo, _ret, errmsg, _cardno, _cur])

		obj.timers.count('db')
		obj.status = _ret.getvalue()
		if obj.status == '0010':
			obj.parser.CardNo, obj.status = _cardno.getvalue(), 'Query Next';
		elif obj.status == '0000':
			cur = result[5]
			try:
				r = cur.next()
			except StopIteration:
				obj.status, obj.parser.ErrInfo = '0025', '无此单号'
			else:
				obj.parser.detail = {'OPERATOR_NAME':r[0],'POS_NO':r[1],'TRANS_NO':r[2],'CANCEL_TRANS_NO':r[3],'BAT_NO':r[4],'TRADE_NO':r[5],'MONEY':r[6], 'PV_MONEY':r[7],'POINT_RATIO':r[8],'TRANS_FLAG':r[9],'POINT_THIS':r[10],'POINT_ALL':r[11],'TRANS_TIME':r[12],'CARD_NO':r[13]}
			cur.close()
		else:
			obj.parser.ErrInfo = errmsg.getvalue()

	def doUpdateRates(self, c, obj):
		self.buildSerialNo(obj)
		posNo, i = obj.parser.EntNo + obj.parser.PosNo, 0
		obj.timers.count('predb')

		#多个循环调用P_GY_POS_RATE_SET
		while i < obj.parser.jfblNum:
			_ret = c.var(cx_Oracle.STRING)
			rate, idx =  '%.4f' % (int(obj.parser.jfbls[i])/10000.0,), '%d'%(i+1,)
			obj.sql = 'P_GY_POS_RATE_SET %s, %s, %s, %s' % (posNo, rate, idx, obj.parser.oper)

			c.callproc('P_GY_POS_RATE_SET', [posNo, rate, idx, obj.parser.oper, _ret])

			if _ret.getvalue() != '0000':
				break
			i += 1

		obj.timers.count('db')
		obj.status = _ret.getvalue()

	def doSyncVars(self, c, obj):
		self.buildSerialNo(obj)
		posno, _ret, retmsg, _baseDBVer, _entName, _entPhone, _entWeb, _currDBVer, _currency, _couDBVer, _couDBNum, _country = obj.parser.EntNo+obj.parser.PosNo, c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR), c.var(cx_Oracle.STRING), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.CURSOR)
		obj.sql = 'P_GY_POS_SYNC %s, %s, %s, %s, %s, %s, %s' % (obj.parser.EntNo, posno, obj.parser.PosCode, obj.parser.baseVer, obj.parser.currencyVer, obj.parser.countryVer, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_SYNC', [obj.parser.EntNo, posno, obj.parser.PosCode, obj.parser.baseVer, obj.parser.currencyVer, obj.parser.countryVer, obj.parser.oper, '', _ret, retmsg, _baseDBVer, _entName, _entWeb, _entPhone, _currDBVer, _currency, _couDBVer, _couDBNum, _country])

		obj.timers.count('db')
		obj.status = _ret.getvalue()
		if obj.status == '0000':	#如果数据库返回错误就没必要取后面数据了
			#取基础信息
			obj.parser.baseDBVer, obj.parser.entDBName, obj.parser.entDBPhone, obj.parser.entDBWeb = _baseDBVer.getvalue(), _entName.getvalue(), _entPhone.getvalue(), _entWeb.getvalue()
			#取货币变更
			obj.parser.currencys, obj.parser.currDBVer = [], _currDBVer.getvalue()
			if int(obj.parser.currDBVer) > int(obj.parser.currencyVer):
				for r in result[15]:
					obj.parser.currencys.append([r[0], r[1], r[2]])
				result[15].close()
				if len(obj.parser.currencys) != 6:
					obj.status = '9997'

		if obj.status == '0000':	#如果获取货币相关信息错误就不用再取国家信息了
			#取国家变更
			obj.parser.countrys, obj.parser.countryDBVer, obj.parser.countryNum = [], _couDBVer.getvalue(), _couDBNum.getvalue()
			if int(obj.parser.countryDBVer) > int(obj.parser.countryVer) and obj.parser.countryNum > 0:
				for r in result[18]:
					obj.parser.countrys.append([r[0], r[1], r[2]])
				result[18].close()

			if len(obj.parser.countrys) != obj.parser.countryNum:
				obj.status = '9997'

	def doQueryEntInfo(self, c, obj):
		posno, ret, retmsg, baseVer, moneyVer, countryVer, EntName, url, phone, countryNum, moneyCur, countryCur = obj.parser.EntNo+obj.parser.PosNo, c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.NUMBER), c.var(cx_Oracle.CURSOR), c.var(cx_Oracle.CURSOR)
		obj.sql = "P_GY_POS_SYNC %s, %s %s, 0, 0, 0, %s, %s" % (obj.parser.EntNo, posno, obj.parser.PosCode, obj.parser.oper, obj.parser.pwd)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_SYNC', [obj.parser.EntNo, posno, obj.parser.PosCode, '0', '0', '0', obj.parser.oper, obj.parser.pwd, ret, retmsg, baseVer, EntName, url, phone, moneyVer, moneyCur, countryVer, countryNum, countryCur])

		obj.timers.count('db')
		obj.status = ret.getvalue()
		if obj.status != '0000':
			obj.parser.CardNo = ''	#返回错误信息
		else:
			obj.parser.baseVer, obj.parser.moneyVer, obj.parser.countryVer, obj.parser.EntName, obj.parser.url, obj.parser.phone, obj.parser.currency, _cur1, obj.parser.country, _cur2 = baseVer.getvalue(), moneyVer.getvalue(), countryVer.getvalue(), EntName.getvalue(), url.getvalue(), phone.getvalue(), [], result[15], [], result[18]

			for r in _cur1:
				#obj.parser.currency.append(struct.pack('3s10s', r[1], r[2]))
				#左补0
				obj.parser.currency.append(struct.pack('3s10s', r[1], ('%10s'%r[2]).replace(' ', '\x00')))
			_cur1.close()

			for r in _cur2:
				#obj.parser.country.append(struct.pack('3s', r[1]))
				if int(r[2]) != 0:
					obj.parser.country.append('%03d%s' % (r[0], r[1]))
			_cur2.close()

	def doQueryOrders(self, c, obj):
		ret, _cur = c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR)
		obj.sql = 'P_GY_TOOLS_APPLIST %s' % obj.parser.oper
		obj.timers.count('predb')

		result = c.callproc('P_GY_TOOLS_APPLIST', ['', '', '11', '', '', 'POS', obj.parser.oper, obj.parser.pwd, ret, _cur])

		obj.timers.count('db')
		cur, obj.status, obj.parser.count, obj.parser.applist = result[9], ret.getvalue(), 0, []
		if obj.status == '0000':
			for r in cur:
				obj.parser.count += 1
				entname = r[2].decode('utf8').encode('gbk')
				d = struct.pack('40s11s40s', r[0], r[3], entname)		#订单号，企业资源号，单位名称
				obj.parser.applist.append(d)
			cur.close()

	def doQueryOrderDetail(self, c, obj):
		ret, _cur, orderno = c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR), cut(obj.parser.OrderNo)
		obj.sql = 'P_GY_POS_UNCONFIG %s' % orderno
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_UNCONFIG', [orderno, obj.parser.oper, obj.parser.pwd, ret, _cur])

		obj.timers.count('db')
		cur, obj.status, obj.count, obj.parser.poslist = result[4], ret.getvalue(), 0, []
		if obj.status == '0000':
			for r in cur:
				obj.count += 1
				obj.parser.poslist.append([r[2], r[3]])
		cur.close()

	def doPosConfiged(self, c, obj):
		_ret, _msg = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING)
		posno = obj.parser.EntNo + obj.parser.PosNo
		obj.sql = 'P_GY_POS_CONFIGED %s, %s, %s, %s' % (posno, obj.parser.PosCode, obj.parser.oper, obj.parser.operation_result)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_CONFIGED', [posno, obj.parser.PosCode, obj.parser.oper, obj.parser.pwd, obj.parser.operation_result, _ret, _msg])

		obj.timers.count('db')
		obj.status, obj.parser.ErrInfo = _ret.getvalue(), _msg.getvalue()

	def doSignIn(self, c, obj):
		_ret, _msg = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING)
		self.buildSerialNo(obj)
		obj.sql = 'P_GY_POS_SIGN %s, I, %s' % (obj.parser.EntNo+obj.parser.PosNo, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_SIGN', [obj.parser.EntNo+obj.parser.PosNo, 'I', obj.parser.oper, _ret, _msg])

		obj.timers.count('db')
		obj.status, obj.parser.ErrInfo = _ret.getvalue(), _msg.getvalue()

	def doSignOff(self, c, obj):
		_ret, _msg = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING)
		self.buildSerialNo(obj)
		obj.sql = 'P_GY_POS_SIGN %s, O, %s' % (obj.parser.EntNo+obj.parser.PosNo, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_SIGN', [obj.parser.EntNo+obj.parser.PosNo, 'O', obj.parser.oper, _ret, _msg])

		obj.timers.count('db')
		obj.status, obj.parser.ErrInfo = _ret.getvalue(), _msg.getvalue()

	def doBatchSettle(self, c, obj):
		_ret, _balAcc = c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING)
		self.buildSerialNo(obj)
		posNo, jfze = obj.parser.EntNo+obj.parser.PosNo, '%.2f' % (obj.parser.jfze/100.0,)
		if obj.parser.cdze > 0:
			cdze = '-%.2f' % (obj.parser.cdze/100.0,)
		else:
			cdze = '0.0'
		obj.sql = 'P_GY_POINTS_BAT_SETTLE %s, %s, %d, %s, %d, %s, %s' % (posNo, obj.parser.batchNo, obj.parser.jfbs, jfze, obj.parser.cdbs, cdze, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POINTS_BAT_SETTLE', [posNo, obj.parser.batchNo, obj.parser.jfbs, jfze, obj.parser.cdbs, cdze, obj.parser.oper, _ret, _balAcc])

		obj.timers.count('db')
		obj.status = _ret.getvalue()
		if obj.status == '0000':
			balAcc = _balAcc.getvalue()
			if balAcc[0:1] in ['Y', 'y']:
				obj.parser.BalAcc = '1'
			else:
				obj.parser.BalAcc = '2'
		else:
			obj.parser.BalAcc = '2'

	def doBatchUpload(self, c, obj):
		self.buildSerialNo(obj)
		posNo, _ret, _res = obj.parser.EntNo + obj.parser.PosNo, c.var(cx_Oracle.STRING), c.var(cx_Oracle.CURSOR)
		obj.sql = 'P_GY_POS_BAT_QRY %s, %s, %s'%(posNo, obj.parser.batchNo, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POS_BAT_QRY', [posNo, obj.parser.batchNo, obj.parser.oper, _ret, _res])

		obj.timers.count('db')
		obj.deals = {}
		for r in result[4]:
			ent = {'PosSerial':r[2], 'db_CardNo':r[3], 'db_DealSum':r[4], 'db_DealRate':r[5], 'db_DealPtSum':r[6], 'db_DealPts':r[7]}
			obj.deals[r[2]] = ent

	def doBatchOK(self, c, obj):
		self.buildSerialNo(obj)
		posNo = obj.parser.EntNo + obj.parser.PosNo
		sqlparams1_2 = "INSERT INTO T_GY_POS_ACCT_CHECK (GY_POS_ACCT_CHECK_ID, GY_POS_NO, GY_BAT_NO, GY_TRADE_NO, GY_CARD_NO_POS, GY_ORDER_AMOUNT_POS, GY_POINTS_RATIO_POS, GY_ASSURE_OUT_VALUE_POS, GY_POINTS_VALUE_POS, GY_CARD_NO_DB, GY_ORDER_AMOUNT_DB, GY_POINTS_RATIO_DB, GY_ASSURE_OUT_VALUE_DB, GY_POINTS_VALUE_DB, GY_OPERATER, GY_SETTLE_RESULT) VALUES(F_GY_GET_TBID('T_GY_POS_ACCT_CHECK'), '%s', '%s', :PosSerial, :CardNo, :DealSum, :DealRate, :DealPtSum, :DealPts, :db_CardNo, :db_DealSum, :db_DealRate, :db_DealPtSum, :db_DealPts, '%s', :Result)" % (posNo, obj.parser.batchNo, obj.parser.oper)
		sqlparams3 = "INSERT INTO T_GY_POS_ACCT_CHECK (GY_POS_ACCT_CHECK_ID, GY_POS_NO, GY_BAT_NO, GY_TRADE_NO, GY_CARD_NO_POS, GY_ORDER_AMOUNT_POS, GY_POINTS_RATIO_POS, GY_ASSURE_OUT_VALUE_POS, GY_POINTS_VALUE_POS, GY_CARD_NO_DB, GY_ORDER_AMOUNT_DB, GY_POINTS_RATIO_DB, GY_ASSURE_OUT_VALUE_DB, GY_POINTS_VALUE_DB, GY_OPERATER, GY_SETTLE_RESULT) VALUES(F_GY_GET_TBID('T_GY_POS_ACCT_CHECK'), '%s', '%s', :PosSerial, :CardNo, :DealSum, :DealRate, :DealPtSum, :DealPts, null, null, null, null, null, '%s', :Result)" % (posNo, obj.parser.batchNo, obj.parser.oper)
		sqlparams4 = "INSERT INTO T_GY_POS_ACCT_CHECK (GY_POS_ACCT_CHECK_ID, GY_POS_NO, GY_BAT_NO, GY_TRADE_NO, GY_CARD_NO_POS, GY_ORDER_AMOUNT_POS, GY_POINTS_RATIO_POS, GY_ASSURE_OUT_VALUE_POS, GY_POINTS_VALUE_POS, GY_CARD_NO_DB, GY_ORDER_AMOUNT_DB, GY_POINTS_RATIO_DB, GY_ASSURE_OUT_VALUE_DB, GY_POINTS_VALUE_DB, GY_OPERATER, GY_SETTLE_RESULT) VALUES(F_GY_GET_TBID('T_GY_POS_ACCT_CHECK'), '%s', '%s', :PosSerial, :db_CardNo, null, null, null, null, :db_CardNo, :db_DealSum, :db_DealRate, :db_DealPtSum, :db_DealPts, '%s', :Result)" % (posNo, obj.parser.batchNo, obj.parser.oper)
		sqlparams5 = "INSERT INTO T_GY_POS_ACCT_CHECK (GY_POS_ACCT_CHECK_ID, GY_POS_NO, GY_BAT_NO, GY_TRADE_NO, GY_CARD_NO_POS, GY_ORDER_AMOUNT_POS, GY_POINTS_RATIO_POS, GY_ASSURE_OUT_VALUE_POS, GY_POINTS_VALUE_POS, GY_CARD_NO_DB, GY_ORDER_AMOUNT_DB, GY_POINTS_RATIO_DB, GY_ASSURE_OUT_VALUE_DB, GY_POINTS_VALUE_DB, GY_OPERATER, GY_SETTLE_RESULT) VALUES(F_GY_GET_TBID('T_GY_POS_ACCT_CHECK'), '%s', '%s', :PosSerial, '', null, null, null, null, null, null, null, null, null, '%s', :Result)" % (posNo, obj.parser.batchNo, obj.parser.oper)

		M1_2, M3, M4, M5 = [], [], [], []
		for k in obj.deals:
			ent = obj.deals[k]
			res = ent['Result']
			if res in ['1', '2']:
				M1_2.append(ent)
			elif res == '3':
				M3.append(ent)
			elif res == '4':
				M4.append(ent)
			else:
				M5.append(ent)
		obj.timers.count('predb')

		if len(M1_2) > 0:
			obj.sql = '%s ---- Params:\n%s' % (sqlparams1_2, str(M1_2))
			c.executemany(sqlparams1_2, M1_2)
		if len(M3) > 0:
			obj.sql = '%s ---- Params:\n%s' % (sqlparams3, str(M3))
			c.executemany(sqlparams3, M3)
		if len(M4) > 0:
			obj.sql = '%s ---- Params:\n%s' % (sqlparams4, str(M4))
			c.executemany(sqlparams4, M4)
		if len(M5) > 0:
			obj.sql = '%s ---- Params:\n%s' % (sqlparams5, str(M5))
			c.executemany(sqlparams5, M5)
		self.conn.commit()

		obj.timers.count('db')
		obj.status = '0000'

	def doPositive(self, c, obj):
		posNo, je, _ret, _bcjf, _jfye = obj.parser.EntNo+obj.parser.PosNo, '%.2f' % (obj.parser.je/100.0,), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING), c.var(cx_Oracle.STRING)
		self.buildSerialNo(obj)
		obj.sql = 'P_GY_POINTS_REVERSAL %s, %s, %s, %s, %s, %s, %s, %s' % (obj.parser.EntNo, obj.parser.CardNo, obj.parser.EntNo+obj.parser.serialno, je, obj.parser.orgBatch, obj.parser.orgSerial, posNo, obj.parser.oper)
		obj.timers.count('predb')

		result = c.callproc('P_GY_POINTS_REVERSAL', [obj.parser.EntNo, obj.parser.CardNo, obj.parser.EntNo+obj.parser.serialno, je, '', obj.parser.orgBatch, obj.parser.orgSerial, posNo, obj.parser.oper, _ret, _bcjf, _jfye])

		obj.timers.count('db')
		obj.status, obj.parser.ErrInfo, obj.parser.ReverRes = _ret.getvalue(), _bcjf.getvalue(), _jfye.getvalue()
		if obj.status == '0010':
			obj.status = 'Positive Next'
		else:
			if obj.status[-2:] != '00' and obj.status[-2:] != '99' and obj.status[-2:] != '12':
				obj.status, obj.parser.ErrInfo = '0025', '无此单号'

class dbFaker(dbVisitor):
	def __init__(self):
		super(dbFaker, self).__init__()
		self.iError, self.reserveData = 0, None

	def doPV(self, c, obj):
		self.buildSerialNo(obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'
		obj.parser.bcjf = 257
		obj.parser.jfye = 63118

	def doCancel(self, c, obj):
		self.buildSerialNo(obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'
		obj.parser.bcjf = -1880
		obj.parser.jfye = 61080

	def doQuerys(self, c, obj):
		return super(dbFaker, self).doQuerys(c, obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'
		obj.parser.count = 1
		obj.parser.presDial = []
		obj.parser.presDial.append({})

	def doQuery(self, c, obj):
		return super(dbFaker, self).doQuery(c, obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'
		obj.parser.detail = {}

	def doUpdateRates(self, c, obj):
		return super(dbFaker, self).doUpdateRates(c, obj)

	def doSyncVars(self, c, obj):
		return super(dbFaker, self).doSyncVars(c, obj)

	def doSetPtScale(self, c, obj):
		return super(dbFaker, self).doSetPtScale(c, obj)

	def doQueryEntInfo(self, c, obj):
		return super(dbFaker, self).doQueryEntInfo(c, obj)

	def doQueryOrders(self, c, obj):
		return super(dbFaker, self).doQueryOrders(c, obj)

	def doQueryOrderDetail(self, c, obj):
		return super(dbFaker, self).doQueryOrderDetail(c, obj)

	def doSignIn(self, c, obj):
		self.buildSerialNo(obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'

	def doSignOff(self, c, obj):
		self.buildSerialNo(obj)
		obj.timers.count('predb')
		time.sleep(TestWait)
		obj.timers.count('db')
		obj.status = '0000'

	def doBatchSettle(self, c, obj):
		return super(dbFaker, self).doBatchSettle(c, obj)

	def doBatchUpload(self, c, obj):
		return super(dbFaker, self).doBatchUpload(c, obj)

	def doBatchOK(self, c, obj):
		return super(dbFaker, self).doBatchOK(c, obj)

	def doPositive(self, c, obj):
		return super(dbFaker, self).doPositive(c, obj)

class db_thread(threading.Thread):
	def __init__(self, c, dber):
		super(db_thread, self).__init__()
		self.dber, self.sock, self.conn = dber, c.socket(zmq.REP), cx_Oracle.Connection(user=DBUSER, password=DBPWD, dsn=DSN, threaded=True)
		self.sock.connect('inproc://' + str(os.getpid()))

	def run(self):
		while 1:
			if self.dber.reserveData is None:
				self.obj = self.sock.recv_pyobj()
			else:
				self.obj = self.dber.reserveData
				try:
					self.conn = cx_Oracle.Connection(user=DBUSER, password=DBPWD, dsn=DSN, threaded=True)
				except:
					posp.logger.exception('Connect Oracle Error.')
					time.sleep(1)
					continue

			x = posp.add_timer(DB_TIMEOUT, self.db_timeout, time.time())
			self.dber.dispatch(self.conn, self.obj)
			posp.del_timer(x)

			if self.dber.reserveData is None:
				self.sock.send_pyobj(self.obj)

	def db_timeout(self, args):
		self.dber.iError = 1
		posp.logger.error('sql: %s\ntimeout: %f' % (self.obj.sql, time.time() - args[0]))
		self.conn.cancel()
		self.conn = cx_Oracle.Connection(user=DBUSER, password=DBPWD, dsn=DSN, threaded=True)

def db_process():
	ff = open('pid.pid', 'a')
	ff.write('%d\n' % os.getpid())
	ff.close()

	posp.logger = logging.getLogger('P(%d)' % os.getpid())
	if GYDEBUG == False:
		posp._hexdump = posp.hexdumpNone

	dber = dbVisitor()
#	dber = dbFaker()
	c = zmq.Context()
	dbproxy = c.socket(zmq.DEALER)
	dbproxy.connect(zmq_dbhub2proxy)

	dbpub = c.socket(zmq.DEALER)
	dbpub.bind('inproc://' + str(os.getpid()))

	poller = zmq.Poller()
	poller.register(dbproxy, zmq.POLLIN)
	poller.register(dbpub, zmq.POLLIN)

	posp.time_reactor()

	os.environ['NLS_LANG'] = 'SIMPLIFIED CHINESE_CHINA.UTF8'
	for x in xrange(DB_CONN):
		t = db_thread(c, dber)
		t.daemon = True
		t.start()

	while 1:
		socks = dict(poller.poll())

		if dbproxy in socks and socks[dbproxy] == zmq.POLLIN:
			_id = dbproxy.recv()
			obj = dbproxy.recv_pyobj()
			obj._id = _id
			dbpub.send('', zmq.SNDMORE)
			dbpub.send_pyobj(obj)

		if dbpub in socks and socks[dbpub] == zmq.POLLIN:
			_ = dbpub.recv()
			obj = dbpub.recv_pyobj()
			dbproxy.send(obj._id, zmq.SNDMORE)
			dbproxy.send_pyobj(obj)

def db_dispatcher():
	'''DBHub进程，负责代理对某一台数据库机器的所有中间件访问
	它会将所有访问请求平衡的分发给数据库访问进程，并收集数据库访问进程的数据，返回给原始请求方
	'''
	ff = open('pid.pid', 'a')
	ff.write('%d\n' % os.getpid())
	ff.close()

	posp.logger = logging.getLogger('D(%d)' % os.getpid())

	c = zmq.Context()
	frontend = c.socket(zmq.ROUTER)
	frontend.bind(zmq_dbhub2worker)
	backend = c.socket(zmq.DEALER)
	backend.bind(zmq_dbhub2proxy)

	poller = zmq.Poller()
	poller.register(frontend, zmq.POLLIN)
	poller.register(backend, zmq.POLLIN)

	while 1:
		socks = dict(poller.poll())
		if frontend in socks and socks[frontend] == zmq.POLLIN:
			_id = frontend.recv()
			req = frontend.recv_pyobj()
			posp.logger.debug('dbhub -> dber')
			backend.send(_id, zmq.SNDMORE)
			backend.send_pyobj(req)

		if backend in socks and socks[backend] == zmq.POLLIN:
			_id = backend.recv()
			obj = backend.recv_pyobj()
			posp.logger.debug('dbhub -> worker')
			frontend.send(_id, zmq.SNDMORE)
			frontend.send_pyobj(obj)

	frontend.close()
	backend.close()
	c.term()

def dber_process(dbproxy_num):
	'''启动数据库代理进程和访问进程
	dbproxy_num - 一共有多少个进程连接DB，每个进程维护一条到Oracle的连接
	'''
	ff = open('pid.pid', 'a')
	ff.write('%d\n' % os.getpid())
	ff.close()

	assert(dbproxy_num >= 1)

	lstp = []
	for i in xrange(dbproxy_num):
	    p = Process(target=db_process)
	    lstp.append(p)
	    p.start()

	db_dispatcher()

	for p in lstp:
		p.join()

	zmq.close()
	zmq.term()
