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
http://localhost:15004/dot?inj=*
http://localhost:15004/blind/dot?inj=*
http://localhost:15004/dust?inj=*
http://localhost:15004/blind/dust?inj=*
http://localhost:15004/marko?inj=*
http://localhost:15004/blind/marko?inj=*
http://localhost:15004/ejs?inj=*
http://localhost:15004/blind/ejs?inj=*

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{

  echo "$webserver_banner"
  
  cd ./env_node_tests/lib/
    
  if [ ! -d ./node_modules/ ]; then
    npm install randomstring
    npm install connect
    npm install jade
    npm install nunjucks
    # Install deprecated dustjs-helpers to have an exploitable
    # if function.
    # See https://github.com/linkedin/dustjs-helpers/pull/110 
    npm install dustjs-linkedin@2.6
    npm install dustjs-helpers@1.5.0
    npm install dot
    npm install marko
    npm install ejs
  fi

  cp ../connect-app.js connect-app.js

  exec node connect-app.js &> $webserver_log

}

if [[ "$1" == "--test" ]]; then
  
  if [ "$#" -gt 1 ]; then
    TESTS="$2"
  else
    TESTS="*"
  fi
  
  echo 'Run web server and launch tests'
  run_webserver &
  NODEPID=$!

  while ! echo | nc localhost 15004; do sleep 1; done

  python -m unittest discover . "test_node_$TESTS.py"

  # Shutdown node webserver
  kill ${NODEPID}
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
