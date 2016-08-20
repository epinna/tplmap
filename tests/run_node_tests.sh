#!/bin/bash

# Jade Plugin exploits execSync() which as been introduced in node 0.11. Node >=0.11
node -v >/dev/null 2>&1 || { echo >&2 "Node required but it's not installed.  Aborting."; exit 1; }
npm -v >/dev/null 2>&1 || { echo >&2 "NPM required but it's not installed.  Aborting."; exit 1; }

NODEPID=0

mkdir -p ./env_node_tests/lib/ 2> /dev/null

webserver_log=$(mktemp)
webserver_banner="Exposed testing APIs:

http://localhost:15004/jade?inj=*
http://localhost:15004/blind/jade?inj=*
http://localhost:15004/nunjucks?inj=*
http://localhost:15004/blind/nunjucks?inj=*
http://localhost:15004/javascript?inj=*
http://localhost:15004/blind/javascript?inj=*

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{

  echo "$webserver_banner"

  if [ ! -d ./node_modules/ ]; then
    npm install connect
    npm install jade
    npm install nunjucks
    npm install --save --production dustjs-linkedin
  fi

  cd ./env_node_tests/lib/

  cp ../connect-app.js connect-app.js

  exec node connect-app.js &> $webserver_log

}

if [[ "$1" == "--test" ]]; then
  echo 'Run web server and launch tests'
  run_webserver &
  NODEPID=$!

  while ! echo | nc localhost 15004; do sleep 1; done

  python -m unittest discover . 'test_node_*.py'

  # Shutdown node webserver
  kill ${NODEPID}
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
