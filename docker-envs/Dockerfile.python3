FROM python:2.7.15

RUN apt-get update && apt-get install dnsutils python3-pip -y
RUN pip3 install mako jinja2 flask tornado
RUN pip install PyYAML requests

COPY  . /apps/
WORKDIR /apps/tests/

RUN sed -i 's/127\.0\.0\.1/0.0.0.0/' env_py_tests/webserver.py

EXPOSE 15001

CMD python3 env_py_tests/webserver.py
