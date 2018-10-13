FROM gradle:4.10.2-jdk8

USER root

RUN apt-get update && apt-get install --upgrade dnsutils python-pip -y
RUN pip install requests PyYAML

COPY tests/env_java_tests/spark-app/ /apps/tests/env_java_tests/spark-app/
WORKDIR /apps/tests/

# install dependencies
RUN cd env_java_tests/spark-app/ && sed -ie 's/id "com\.github\.johnrengelman\.shadow".*//' build.gradle && \
    gradle classes

COPY . /apps/

EXPOSE 15003

CMD cd env_java_tests/spark-app/ && gradle run
