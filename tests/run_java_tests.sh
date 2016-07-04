#!/bin/bash

gradle -v >/dev/null 2>&1 || { echo >&2 "Gradle required but it's not installed.  Aborting."; exit 1; }
type nc >/dev/null 2>&1 || { echo >&2 "Netcat required but it's not installed.  Aborting."; exit 1; }

#if [ ! -d ./_test_java_freemarker/lib/spark-example/ ]; then
rm  -rf ./_test_java_freemarker/lib/spark-app/
cp -rf ./_test_java_freemarker/spark-app ./_test_java_freemarker/lib/spark-app/
#fi

cd ./_test_java_freemarker/lib/spark-app/
gradle run --debug&
GRADLEPID=$!

while ! echo exit | nc localhost 15001; do sleep 10; done

cd ../../../
python -m unittest discover . 'test_java_*.py'
sleep 1
# Shutdown Java webserver 
kill ${GRADLEPID}
