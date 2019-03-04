#!/bin/sh

GYDEBUG=`awk '/^GYDEBUG/' ./gyconfig.py | awk '{print $3}'`
CACHEADDR=`awk '/^cache_addr/' ./gyconfig.py | awk '{print $3}' | awk 'BEGIN{FS="[:'\'']"}{print $2}'`
CACHEPORT=`awk '/^cache_addr/' ./gyconfig.py | awk '{print $3}' | awk 'BEGIN{FS="[:'\'']"}{print $3}'`

CHECKCACHE=`./monitor_memcached.sh $CACHEADDR $CACHEPORT`
if [ ${#CHECKCACHE} = 0 ]; then
	echo Cache Server not Started! Please Start the Cache Server.
else
	echo $CHECKCACHE
fi

if [ x"$GYDEBUG" = x"True" ]; then
	python ./gymidder.py -dispatcher
else
	python -O gymidder.py -dispatcher
fi
