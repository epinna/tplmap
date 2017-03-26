#!/bin/bash

# TODO: check if php supports -S option
php -v >/dev/null 2>&1 || { echo >&2 "PHP CLI required but it's not installed.  Aborting."; exit 1; }

PHPPID=0

mkdir -p ./env_php_tests/lib/ 2> /dev/null

webserver_log=$(mktemp)
webserver_banner="Exposed testing APIs:

http://localhost:15002/smarty-3.1.29-secured.php?inj=*
http://localhost:15002/smarty-3.1.29-unsecured.php?inj=*
http://localhost:15002/smarty-3.1.29-unsecured.php?inj=*&blind=1
http://localhost:15002/twig-1.24.1-secured.php?inj=*
http://localhost:15002/eval.php?inj=*
http://localhost:15002/eval.php?inj=*&blind=1

Web server standard output and error are redirected to file
$webserver_log
"

# Run  webserver
function run_webserver()
{

  echo "$webserver_banner"

  # Download smarty 3.1.29 if not already installed
  if [ ! -d ./env_php_tests/lib/smarty-3.1.29/ ]; then
      wget https://github.com/smarty-php/smarty/archive/v3.1.29.tar.gz -O ./env_php_tests/lib/v3.1.29.tar.gz
      tar xvf ./env_php_tests/lib/v3.1.29.tar.gz -C ./env_php_tests/lib/
      rm ./env_php_tests/lib/v3.1.29.tar.gz
  fi
  # Download twig 1.24.1 if not already installed
  if [ ! -d ./env_php_tests/lib/twig-1.24.1/ ]; then
      wget https://github.com/twigphp/Twig/archive/v1.24.1.tar.gz -O ./env_php_tests/lib/v1.24.1.tar.gz
      tar xvf ./env_php_tests/lib/v1.24.1.tar.gz -C ./env_php_tests/lib/
      rm ./env_php_tests/lib/v1.24.1.tar.gz
  fi

  # Run PHP webserver
  exec php -S 127.0.0.1:15002 -t env_php_tests/ &> $webserver_log
}


if [[ "$1" == "--test" ]]; then
  
  if [ "$#" -gt 1 ]; then
    TESTS="$2"
  else
    TESTS="*"
  fi
  
  echo 'Run web server and launch tests'
  run_webserver &
  PHPPID=$!

  while ! echo | nc localhost 15002; do sleep 1; done

  python -m unittest discover . "test_php_$TESTS.py"

  # Shutdown PHP webserver
  kill ${PHPPID}
else
  echo 'Starting web server. Press ctrl-C to quit. Run with --test to run automated tests.'
  run_webserver
fi
