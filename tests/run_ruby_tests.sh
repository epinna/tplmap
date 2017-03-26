#!/bin/bash

curl --version >/dev/null 2>&1 || { echo >&2 "Curl required but it's not installed.  Aborting."; exit 1; }
ruby --version >/dev/null 2>&1 || { echo >&2 "Ruby is required but it's not installed.  Aborting."; exit 1; }
gem list -i "cuba" >/dev/null 2>&1 || { echo >&2 "'cuba' ruby gem is required but it's not installed.  Aborting."; exit 1; }
gem list -i "tilt" >/dev/null 2>&1 || { echo >&2 "'tilt' ruby gem is required but it's not installed.  Aborting."; exit 1; }
gem list -i "slim" >/dev/null 2>&1 || { echo >&2 "'slim' ruby gem is required but it's not installed.  Aborting."; exit 1; }
rackup --version >/dev/null 2>&1 || { echo >&2 "Ruby Rackup is required but it's not installed.  Aborting."; exit 1; }


webserver_log=$(mktemp)
webserver_banner="Exposed testing APIs:

http://localhost:15005/reflect/eval?inj=*
http://localhost:15005/blind/eval?inj=*
http://localhost:15005/reflect/slim?inj=*
http://localhost:15005/blind/slim?inj=*
http://localhost:15005/reflect/erb?inj=*
http://localhost:15005/blind/erb?inj=*

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{
    echo "$webserver_banner"

    cd env_ruby_tests/
    rackup --port 15005 &> $webserver_log
    cd ..
}


if [[ "$1" == "--test" ]]; then
  
  if [ "$#" -gt 1 ]; then
    TESTS="$2"
  else
    TESTS="*"
  fi
  
  echo 'Run web server and launch tests'
  run_webserver &

  # Wait until the port is open
  while ! echo | curl http://localhost:15005/ -s -o /dev/null; do sleep 1; done
  # Launch python engines tests
  python -m unittest discover . "test_ruby_$TESTS.py"
  # Shutdown python webserver
  curl http://localhost:15005/shutdown -s -o /dev/null
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
