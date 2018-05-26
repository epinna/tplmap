#!/bin/bash -e

INSTANCE_NAME="tplmap-java"
IMAGE_NAME="tplmap-java-img"
PORT=15003

echo "Exposed testing APIs:

http://localhost:15003/velocity?inj=*
http://localhost:15003/velocity?inj=*&blind=1
http://localhost:15003/freemarker?inj=*
http://localhost:15003/freemarker?inj=*&blind=1
"

cd "$( dirname "${BASH_SOURCE[0]}" )"/../

docker rm -f $INSTANCE_NAME || echo ''
docker build -f docker-envs/Dockerfile.java . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the http server is serving
until $(curl --output /dev/null --silent --head http://localhost:$PORT/); do
    sleep 1
done
sleep 1

# Launch Java engines tests
docker exec -it $INSTANCE_NAME python -m unittest discover -v . 'test_java_*.py'

docker stop $INSTANCE_NAME