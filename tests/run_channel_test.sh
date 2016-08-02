#!/bin/bash

type nc >/dev/null 2>&1 || { echo >&2 "Netcat required but it's not installed.  Aborting."; exit 1; }
curl --version >/dev/null 2>&1 || { echo >&2 "Curl required but it's not installed.  Aborting."; exit 1; }
python -c 'import mako' 2>&1 || { echo >&2 "Python Mako required but it's not installed.  Aborting."; exit 1; }
python -c 'import jinja2' 2>&1 || { echo >&2 "Python Jinja2 required but it's not installed.  Aborting."; exit 1; }
python -c 'import flask' 2>&1 || { echo >&2 "Python Flask required but it's not installed.  Aborting."; exit 1; }

webserver_log=$(mktemp)

webserver_banner="Exposed testing APIs:

http://localhost:15001/reflect/mako?inj=*
http://localhost:15001/reflect/jinja2?inj=*
http://localhost:15001/post/mako?inj=*
http://localhost:15001/post/jinja2?inj=*
http://localhost:15001/limit/mako?inj=*
http://localhost:15001/limit/jinja2?inj=*
http://localhost:15001/put/mako?inj=*
http://localhost:15001/put/jinja2?inj=*

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{
    echo "$webserver_banner"
    cd env_py_tests/
    python webserver.py &> $webserver_log
    cd ..
}


if [[ "$1" == "--test" ]]; then
  echo 'Run web server and launch tests'
  run_webserver &

  # Wait until the port is open
  while ! echo | nc localhost 15001; do sleep 1; done
  # Launch python engines tests
  python -m unittest discover . 'test_channel*.py'
  # Shutdown python webserver
  curl http://localhost:15001/shutdown
else
    echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
    run_webserver
fi
