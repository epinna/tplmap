FROM php:latest

RUN apt-get update && apt-get install --upgrade dnsutils python-pip -y
RUN pip install requests PyYAML

COPY  . /apps/
WORKDIR /apps/tests/

RUN mkdir env_php_tests/lib/ && cd env_php_tests/lib && \
    curl -sL 'https://github.com/smarty-php/smarty/archive/v3.1.32.tar.gz' | tar xzf - && \
    curl -sL 'https://github.com/twigphp/Twig/archive/v1.24.1.tar.gz' | tar xzf - && \
    curl -sL 'https://github.com/twigphp/Twig/archive/v1.19.0.tar.gz' | tar xzf -

EXPOSE 15002

CMD cd env_php_tests && php -S 0.0.0.0:15002

