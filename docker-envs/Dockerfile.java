FROM gradle:latest

USER root

RUN apt-get update && apt-get install --upgrade dnsutils python-pip -y
RUN pip install requests PyYAML

COPY  . /apps/
WORKDIR /apps/tests/

# install dependencies
RUN cd env_java_tests/spark-app/ && sed -ie 's/id "com\.github\.johnrengelman\.shadow".*//' build.gradle && \
    gradle classes

EXPOSE 15003

CMD cd env_java_tests/spark-app/ && gradle run
