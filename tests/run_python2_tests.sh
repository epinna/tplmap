#!/bin/bash -e

INSTANCE_NAME="tplmap-py2"
IMAGE_NAME="tplmap-py2-img"
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
docker build -f docker-envs/Dockerfile.python2 . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the http server is serving
until $(curl --output /dev/null --silent --head http://localhost:$PORT/); do
    sleep 1
done

# Launch python engines tests
docker exec -it $INSTANCE_NAME python -m unittest discover -v . 'test_py_*.py'

docker stop $INSTANCE_NAME