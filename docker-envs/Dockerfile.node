FROM node:10.12.0

RUN apt-get update && apt-get install --upgrade dnsutils python-pip libpython-dev -y
RUN pip install requests PyYAML

COPY tests/env_node_tests/ /apps/tests/env_node_tests/

RUN cd /apps/tests/env_node_tests/ && npm install randomstring connect pug nunjucks dustjs-linkedin@2.6 dustjs-helpers@1.5.0 marko dot ejs

EXPOSE 15004

COPY  . /apps/
WORKDIR /apps/tests/

CMD cd /apps/tests/env_node_tests/ && node connect-app.js
