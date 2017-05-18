FROM gradle:latest

WORKDIR /tests
COPY tests/env_java_tests/spark-app .

# install dependencies
USER root
RUN sed -ie 's/id "com\.github\.johnrengelman\.shadow".*//' build.gradle && \
    gradle classes

EXPOSE 15003

CMD ["gradle", "run"]
