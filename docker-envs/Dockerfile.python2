FROM python:2.7.15

RUN pip install mako jinja2 flask tornado PyYAML requests
RUN apt-get update && apt-get install dnsutils -y

COPY  . /apps/
WORKDIR /apps/tests/

RUN sed -i 's/127\.0\.0\.1/0.0.0.0/' env_py_tests/webserver.py

EXPOSE 15001

CMD python env_py_tests/webserver.py
