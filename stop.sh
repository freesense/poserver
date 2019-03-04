#!/bin/sh

if [ -f ./gyconfig.py ];
then
gefil=`awk '/^zmq_gevent2worker/' ./gyconfig.py | awk '{print $3}' | awk 'BEGIN{FS="[:'\'']"}{print $3}'|awk -F'/' '{print $3}'`
dbhub=`awk '/^zmq_dbhub2proxy/' ./gyconfig.py | awk '{print $3}' | awk 'BEGIN{FS="[:'\'']"}{print $3}'|awk -F'/' '{print $3}'`
else
gefil='gevent.worker2'
dbhub='hub.dbproxy2'
fi

if [ -e $gefil ]; then
	rm -fr $gefil
fi
if [ -e $dbhub ]; then
	rm -fr $dbhub
fi

if [ -w pid.pid ];
then
	kill -9 `cat pid.pid`
	rm pid.pid
fi
