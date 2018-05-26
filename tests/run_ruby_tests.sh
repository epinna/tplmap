#!/bin/bash -e

INSTANCE_NAME="tplmap-ruby"
IMAGE_NAME="tplmap-ruby-img"
PORT=15005

echo "Exposed testing APIs:

http://localhost:15005/reflect/eval?inj=*
http://localhost:15005/blind/eval?inj=*
http://localhost:15005/reflect/slim?inj=*
http://localhost:15005/blind/slim?inj=*
http://localhost:15005/reflect/erb?inj=*
http://localhost:15005/blind/erb?inj=*
"

cd "$( dirname "${BASH_SOURCE[0]}" )"/../

docker rm -f $INSTANCE_NAME || echo ''
docker build -f docker-envs/Dockerfile.ruby . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the http server is serving
until $(curl --output /dev/null --silent --head http://localhost:$PORT/); do
    sleep 1
done

# Launch ruby engines tests
docker exec -it $INSTANCE_NAME python -m unittest discover -v . 'test_ruby_*.py'

docker stop $INSTANCE_NAME