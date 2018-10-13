#!/bin/bash -e

INSTANCE_NAME="tplmap-php"
IMAGE_NAME="tplmap-php-img"
PORT=15002

echo "Exposed testing APIs:

http://localhost:15002/smarty-3.1.32-secured.php?inj=*
http://localhost:15002/smarty-3.1.32-unsecured.php?inj=*
http://localhost:15002/smarty-3.1.32-unsecured.php?inj=*&blind=1
http://localhost:15002/twig-1.24.1-secured.php?inj=*
http://localhost:15002/eval.php?inj=*
http://localhost:15002/eval.php?inj=*&blind=1
"

cd "$( dirname "${BASH_SOURCE[0]}" )"/../

docker rm -f $INSTANCE_NAME || echo ''
docker build -f docker-envs/Dockerfile.php . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the http server is serving
until $(curl --output /dev/null --silent --head http://localhost:$PORT/); do
    sleep 1
done

# Launch PHP engines tests
docker exec -it $INSTANCE_NAME python -m unittest discover -v . 'test_php_*.py'

docker stop $INSTANCE_NAME