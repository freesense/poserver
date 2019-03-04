#!/bin/sh

exec 5<> /dev/tcp/$1/$2
if [ $? -eq 0 ]; then
        echo "stats" >&5
        echo "quit" >&5
        while read -u 5 -d $'\r' stat name value;
	        do
    		    if [ x"$name" = x"version" ]; then
        		echo memcached version: $value
        	fi
        	done
        exec 5<&-
        exec 5>&-
        exit 0
fi
exit 1
