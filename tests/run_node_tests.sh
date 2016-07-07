#!/bin/bash

node -v >/dev/null 2>&1 || { echo >&2 "Node required but it's not installed.  Aborting."; exit 1; }
npm -v >/dev/null 2>&1 || { echo >&2 "NPM required but it's not installed.  Aborting."; exit 1; }

NODEPID=0

mkdir -p ./env_node_tests/lib/ 2> /dev/null

# Run  webserver
function run_webserver()
{

  cd ./env_node_tests/lib/

  if [ ! -d ./node_modules/ ]; then
    npm install connect
    npm install jade
  fi

  cp ../connect-app.js connect-app.js

  node connect-app.js
  NODEPID=$!

  cd ../../
}

if [[ "$1" == "--server" ]]; then
  echo 'Raise web server only'
  run_webserver
else
  echo 'Run web server and launch tests'
  run_webserver &

  while ! echo exit | nc localhost 15004; do sleep 3; done

  python -m unittest discover . 'test_node_*.py'

  # Shutdown node webserver
  kill ${NODEPID}
fi
