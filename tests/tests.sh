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
php -S localhost:8000 -t _test_php_smarty/&
PHPPID=$!
sleep 1
# Launch PHP engines tests
python -m unittest discover . 'test_hp_*.py'
sleep 1
# Shutdown PHP webserver 
kill ${PHPPID}
