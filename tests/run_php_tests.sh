#!/bin/bash

# Run PHP webserver
php -S 127.0.0.1:15001 -t _test_php_smarty/&
PHPPID=$!
# Download smarty 3.1.29 if not already installed
if [ ! -d ./_test_php_smarty/lib/smarty-3.1.29/ ]; then
    wget https://github.com/smarty-php/smarty/archive/v3.1.29.tar.gz -O ./_test_php_smarty/lib/v3.1.29.tar.gz
    tar xvf ./_test_php_smarty/lib/v3.1.29.tar.gz -C ./_test_php_smarty/lib/
    rm ./_test_php_smarty/lib/v3.1.29.tar.gz
fi
# Download twig 1.24.1 if not already installed
if [ ! -d ./_test_php_twig/lib/twig-1.24.1/ ]; then
    wget https://github.com/twigphp/Twig/archive/v1.24.1.tar.gz -O ./_test_php_twig/lib/v1.24.1.tar.gz
    tar xvf ./_test_php_twig/lib/v1.24.1.tar.gz -C ./_test_php_twig/lib/
    rm ./_test_php_twig/lib/v1.24.1.tar.gz
fi
sleep 1
# Launch PHP engines tests
python -m unittest discover . 'test_php_*.py'
sleep 1
# Shutdown PHP webserver 
kill ${PHPPID}