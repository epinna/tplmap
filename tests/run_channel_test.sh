#!/bin/bash

cd env_py_tests/
# Run python webserver
python webserver.py&
cd ..
sleep 1
# Launch python engines tests
python -m unittest discover . 'test_channel_*.py'
sleep 1
# Shutdown python webserver
curl http://localhost:15001/shutdown
