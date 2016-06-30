#!/bin/bash

# Start python webserver
python webserver.py&

sleep 1

python -m unittest discover . 'test_*.py'


sleep 1
# Shutdown python webserver 
curl http://localhost:15001/shutdown

