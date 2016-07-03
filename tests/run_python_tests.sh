#!/bin/bash

# Run python webserver
python webserver.py&
sleep 1
# Launch python engines tests
python -m unittest discover . 'test_py_*.py'
sleep 1
# Shutdown python webserver 
curl http://localhost:15001/shutdown