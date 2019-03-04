#!/bin/sh

GYDEBUG=`awk '/^GYDEBUG/' ./gyconfig.py | awk '{print $3}'`
COUNT=`awk '/^PROCESS_COUNT/' ./gyconfig.py | awk '{print $3}'`
if [ x"$GYDEBUG" = x"True" ]
then
	python ./gymidder.py -dber $COUNT
else
	python -O gymidder.py -dber $COUNT
fi