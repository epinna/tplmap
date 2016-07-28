#!/bin/bash

node -v >/dev/null 2>&1 || { echo >&2 "Node required but it's not installed.  Aborting."; exit 1; }
npm -v >/dev/null 2>&1 || { echo >&2 "NPM required but it's not installed.  Aborting."; exit 1; }

NODEPID=0

mkdir -p ./env_node_tests/lib/ 2> /dev/null

webserver_log=$(mktemp)
webserver_banner="Exposed testing APIs:

http://localhost:15004/jade?inj=*
http://localhost:15004/blind/jade?inj=*

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{

  echo "$webserver_banner"

  cd ./env_node_tests/lib/

  if [ ! -d ./node_modules/ ]; then
    npm install connect
    npm install jade
  fi

  cp ../connect-app.js connect-app.js

  exec node connect-app.js &> $webserver_log

}

if [[ "$1" == "--test" ]]; then
  echo 'Run web server and launch tests'
  run_webserver &
  NODEPID=$!

  while ! echo exit | nc localhost 15004; do sleep 3; done

  python -m unittest discover . 'test_node_*.py'

  # Shutdown node webserver
  kill ${NODEPID}
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
