#!/bin/bash

INSTANCE_NAME="tplmap-py"
IMAGE_NAME="tplmap-py-img"
PORT=15001

echo "Exposed testing APIs:

http://localhost:15001/reflect/mako?inj=*
http://localhost:15001/reflect/jinja2?inj=*
http://localhost:15001/post/mako?inj=*
http://localhost:15001/post/jinja2?inj=*
http://localhost:15001/limit/mako?inj=*
http://localhost:15001/limit/jinja2?inj=*
http://localhost:15001/put/mako?inj=*
http://localhost:15001/put/jinja2?inj=*
"

cd "$( dirname "${BASH_SOURCE[0]}" )"/../

docker rm -f $INSTANCE_NAME || echo ''
docker build -f docker-envs/Dockerfile.python . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the port is open
while ! </dev/tcp/localhost/$PORT; do sleep 1; done 2> /dev/null

# Launch python engines tests
python -m unittest discover -v tests/ 'test_channel*.py'

docker stop $INSTANCE_NAME