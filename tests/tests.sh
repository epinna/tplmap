#!/bin/bash

# Run python webserver
python webserver.py&
sleep 1
# Launch python engines tests
python -m unittest discover . 'test_py_*.py'
sleep 1
# Shutdown python webserver 
curl http://localhost:15001/shutdown

# Run PHP webserver
php -S localhost:15001 -t _test_php_smarty/&
PHPPID=$!
# Download smarty if not already installed
if [ ! -d ./_test_php_smarty/smarty/ ]; then
    wget https://github.com/smarty-php/smarty/archive/v3.1.29.tar.gz -O ./_test_php_smarty/v3.1.29.tar.gz
    tar xvf ./_test_php_smarty/v3.1.29.tar.gz -C ./_test_php_smarty/
    mv ./_test_php_smarty/smarty-3.1.29/libs ./_test_php_smarty/smarty/
    rm -r ./_test_php_smarty/smarty-3.1.29/ ./_test_php_smarty/v3.1.29.tar.gz
fi
sleep 1
# Launch PHP engines tests
python -m unittest discover . 'test_php_*.py'
sleep 1
# Shutdown PHP webserver 
kill ${PHPPID}
