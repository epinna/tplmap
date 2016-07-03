#!/bin/bash

gradle -v >/dev/null 2>&1 || { echo >&2 "Gradle required but it's not installed.  Aborting."; exit 1; }

if [ ! -d ./_test_java_freemarker/lib/spark-example/ ]; then
  cp -rf ./_test_java_freemarker/spark-example ./_test_java_freemarker/lib/spark-example/
fi

cd ./_test_java_freemarker/lib/spark-example/
gradle run