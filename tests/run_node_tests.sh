#!/bin/bash

npm -v >/dev/null 2>&1 || { echo >&2 "NPM required but it's not installed.  Aborting."; exit 1; }

mkdir -p ./env_node_tests/lib/ 2> /dev/null

cd ./env_node_tests/lib/

if [ ! -d ./node_modules/ ]; then
  npm install connect
  npm install jade
fi

cp ../connect-app.js connect-app.js 

node connect-app.js &
NODEPID=$!

while ! echo exit | nc localhost 15004; do sleep 1; done

cd ../../
python -m unittest discover . 'test_node_*.py'
sleep 1
# Shutdown Java webserver 
kill ${NODEPID}
