#!/bin/bash

# This requires at least java 1.8
gradle -v >/dev/null 2>&1 || { echo >&2 "Gradle required but it's not installed.  Aborting."; exit 1; }
type nc >/dev/null 2>&1 || { echo >&2 "Netcat required but it's not installed.  Aborting."; exit 1; }

mkdir -p ./env_java_tests/lib/ 2> /dev/null

GRADLEPID=0

webserver_log=$(mktemp)

webserver_banner="Exposed testing APIs:

http://localhost:15003/velocity?inj=*
http://localhost:15003/velocity?inj=*&blind=1
http://localhost:15003/freemarker?inj=*
http://localhost:15003/freemarker?inj=*&blind=1

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{
  echo "$webserver_banner"

  if [ ! -d ./env_java_tests/lib/spark-example/ ]; then
    rm  -rf ./env_java_tests/lib/spark-app/
    cp -rf ./env_java_tests/spark-app ./env_java_tests/lib/spark-app/
  fi

  cd ./env_java_tests/lib/spark-app/
  exec gradle run &> $webserver_log
}


if [[ "$1" == "--test" ]]; then
  
  if [ "$#" -gt 1 ]; then
    TESTS="$2"
  else
    TESTS="*"
  fi
  
  echo 'Run web server and launch tests'
  run_webserver &
  GRADLEPID=$!

  while ! echo | nc localhost 15003; do sleep 1; done

  python -m unittest discover . "test_java_$TESTS.py"

  # Shutdown Java webserver
  kill ${GRADLEPID}
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
