#!/bin/bash

# TODO: check if php supports -S option
php -v >/dev/null 2>&1 || { echo >&2 "PHP CLI required but it's not installed.  Aborting."; exit 1; }

PHPPID=0

mkdir -p ./env_php_tests/lib/ 2> /dev/null

api_string="Exposed testing APIs:

http://localhost:15002/smarty-3.1.29-secured.php?inj=*
http://localhost:15002/smarty-3.1.29-unsecured.php?inj=*
http://localhost:15002/twig-1.24.1-secured.php?inj=*
"

# Run  webserver
function run_webserver()
{

  echo "$api_string"

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
  php -S 127.0.0.1:15002 -t env_php_tests/
  PHPPID=$!
}


if [[ "$1" == "--server" ]]; then
  echo 'Raise web server only'
  run_webserver
else
  echo 'Run web server and launch tests'
  run_webserver &

  while ! echo exit | nc localhost 15002; do sleep 3; done

  python -m unittest discover . 'test_php_*.py'

  # Shutdown PHP webserver
  kill ${PHPPID}
fi
