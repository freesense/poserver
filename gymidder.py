#!/usr/bin/python2.6
#coding: utf-8

#POS机中间件，writen by xinl 2013/03/29

from gyconfig import GYDEBUG, LOGMAXIUM
from logging.handlers import RotatingFileHandler, TimedRotatingFileHandler
import logging, sys, random, os

#重定义输出颜色
COLOR_RED='\033[1;31m'
COLOR_GREEN='\033[1;32m'
COLOR_YELLOW='\033[1;33m'
COLOR_BLUE='\033[1;34m'
COLOR_PURPLE='\033[1;35m'
COLOR_CYAN='\033[1;36m'
COLOR_GRAY='\033[1;37m'
COLOR_WHITE='\033[1;38m'
COLOR_RESET='\033[1;0m'

LOG_COLORS = {
	'DEBUG':	COLOR_BLUE + 'DEBUG' + COLOR_RESET,
	'INFO':		COLOR_GREEN + 'INFO' + COLOR_RESET,
	'WARNING':	COLOR_YELLOW + 'WARNING' + COLOR_RESET,
	'ERROR':	COLOR_RED + 'ERROR' + COLOR_RESET,
	'CRITICAL':	COLOR_PURPLE + 'CRITICAL' + COLOR_RESET,
	'EXCEPTION':COLOR_RED + 'EXCEPTION' + COLOR_RESET,
}

class ColoredFormatter(logging.Formatter):
	'''为屏幕日志输出加上颜色格式化
	'''
	def __init__(self, fmt = None, datefmt = None):
		logging.Formatter.__init__(self, fmt, datefmt)

	def format(self, record):
		record.levelname = LOG_COLORS.get(record.levelname, record.levelname)
		return logging.Formatter.format(self, record)

###############################################################################
def daemonize(stdin='/dev/null', stdout='/dev/null', stderr='/dev/null'):
	# Perform first fork.
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0) # Exit first parent.
	except OSError, e:
		sys.stderr.write("fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)
	# Decouple from parent environment.
	os.chdir("./")
	os.umask(0)
	os.setsid()
	# Perform second fork.
	try:
		pid = os.fork()
		if pid > 0:
			sys.exit(0) # Exit second parent.
	except OSError, e:
		sys.stderr.write("fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
		sys.exit(1)
	# The process is now daemonized, redirect standard file descriptors.
#	for f in sys.stdout, sys.stderr:
#		f.flush()
#	si = file(stdin, 'r')
#	so = file(stdout, 'a+')
#	se = file(stderr, 'a+', 0)
#	os.dup2(si.fileno(), sys.stdin.fileno())
#	os.dup2(so.fileno(), sys.stdout.fileno())
#	os.dup2(se.fileno(), sys.stderr.fileno())

if __name__ == '__main__':
	if len(sys.argv) < 2:
		print 'Params: -dispatcher|dber [num]'
		sys.exit(1)

	daemonize()

	random.seed()
	logging.getLogger().level = logging.DEBUG

	#hfile = TimedRotatingFileHandler(os.path.join(os.getcwd(), 'gylog'), LOGROLLFLAG, backupCount=LOGCOUNT)
	hfile = RotatingFileHandler(os.path.join(os.getcwd(), 'gylog'), maxBytes = LOGMAXIUM*1024*1024, backupCount=10)
	if GYDEBUG == False:
		hfile.setLevel(logging.INFO)
	else:
		hfile.setLevel(logging.DEBUG)
	formatter = logging.Formatter('%(asctime)s.PID=%(process)d.%(filename)s.%(lineno)d.%(levelname)s: %(message)s')
	hfile.setFormatter(formatter)
	logging.getLogger().addHandler(hfile)

	console = logging.StreamHandler()
	if GYDEBUG == False:
		console.setLevel(logging.INFO)
	else:
		console.setLevel(logging.DEBUG)
	formatter = ColoredFormatter('%(asctime)s.PID=%(process)d.%(filename)s.%(lineno)d.%(levelname)s: %(message)s')
	console.setFormatter(formatter)
	logging.getLogger().addHandler(console)

	msg = 'Python Version:\n' + sys.version + '\n'
	if __debug__:
		msg += '>>>>> Start service in debug mode.'
	else:
		msg += '>>>>> Start service in release mode.'
	logging.getLogger().info(msg)

	if sys.argv[-1] == '-dispatcher':
		from gevent import monkey; monkey.patch_all()
		from gymidcore import *
		gevent_process()
	elif sys.argv[-2] == '-dber':
		from dber import *
		dber_process(int(sys.argv[-1]))
