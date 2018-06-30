#!/bin/bash -e

INSTANCE_NAME="tplmap-node"
IMAGE_NAME="tplmap-node-img"
PORT=15004

echo "Exposed testing APIs:

http://localhost:15004/pug?inj=*
http://localhost:15004/blind/pug?inj=*
http://localhost:15004/nunjucks?inj=*
http://localhost:15004/blind/nunjucks?inj=*
http://localhost:15004/javascript?inj=*
http://localhost:15004/blind/javascript?inj=*
http://localhost:15004/dot?inj=*
http://localhost:15004/blind/dot?inj=*
http://localhost:15004/dust?inj=*
http://localhost:15004/blind/dust?inj=*
http://localhost:15004/marko?inj=*
http://localhost:15004/blind/marko?inj=*
http://localhost:15004/ejs?inj=*
http://localhost:15004/blind/ejs?inj=*
"

cd "$( dirname "${BASH_SOURCE[0]}" )"/../

docker rm -f $INSTANCE_NAME || echo ''
docker build -f docker-envs/Dockerfile.node . -t $IMAGE_NAME
docker run --rm --name $INSTANCE_NAME -p $PORT:$PORT -d $IMAGE_NAME

# Wait until the http server is serving
until $(curl --output /dev/null --silent --head http://localhost:$PORT/); do
    sleep 1
done

# Launch node engines tests
docker exec -it $INSTANCE_NAME python -m unittest discover -v . 'test_node_*.py'

docker stop $INSTANCE_NAME