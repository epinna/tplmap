#!/bin/bash

gradle -v >/dev/null 2>&1 || { echo >&2 "Gradle required but it's not installed.  Aborting."; exit 1; }
type nc >/dev/null 2>&1 || { echo >&2 "Netcat required but it's not installed.  Aborting."; exit 1; }

mkdir -p ./env_java_tests/lib/ 2> /dev/null

GRADLEPID=0

api_string="Exposed testing APIs:

http://localhost:15003/velocity?inj=*
http://localhost:15003/freemarker?inj=*
"

# Run  webserver
function run_webserver()
{
  echo "$api_string"

  if [ ! -d ./env_java_tests/lib/spark-example/ ]; then
    rm  -rf ./env_java_tests/lib/spark-app/
    cp -rf ./env_java_tests/spark-app ./env_java_tests/lib/spark-app/
  fi

  cd ./env_java_tests/lib/spark-app/
  gradle run
  GRADLEPID=$!
  cd ../../../
}


if [[ "$1" == "--server" ]]; then
  echo 'Raise web server only'
  run_webserver
else
  echo 'Run web server and launch tests'
  run_webserver &

  while ! echo exit | nc localhost 15003; do sleep 3; done


  python -m unittest discover . 'test_java_*.py'

  # Shutdown Java webserver
  kill ${GRADLEPID}
fi
