#!/bin/bash

INSTANCE_NAME="tplmap-node"
IMAGE_NAME="tplmap-node-img"
PORT=15004

echo "Exposed testing APIs:

http://localhost:15004/jade?inj=*
http://localhost:15004/blind/jade?inj=*
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

# Wait until the port is open
while ! </dev/tcp/localhost/$PORT; do sleep 1; done 2> /dev/null

# Launch python engines tests
python -m unittest discover -v tests/ 'test_node_*.py'

docker stop $INSTANCE_NAME