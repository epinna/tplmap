FROM gradle:latest

WORKDIR /tests
COPY tests/env_java_tests/spark-app .

# install dependencies
USER root
RUN sed -ie 's/id "com\.github\.johnrengelman\.shadow".*//' build.gradle && \
    gradle classes
RUN apt-get update && apt-get install dnsutils -y

EXPOSE 15003

CMD ["gradle", "run"]
