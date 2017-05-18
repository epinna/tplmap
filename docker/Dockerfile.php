FROM php:latest

WORKDIR /tests
COPY tests/env_php_tests .

RUN mkdir lib && cd lib && \
    curl -sL 'https://github.com/smarty-php/smarty/archive/v3.1.29.tar.gz' | tar xzf - && \
    curl -sL 'https://github.com/twigphp/Twig/archive/v1.24.1.tar.gz' | tar xzf - && \
    curl -sL 'https://github.com/twigphp/Twig/archive/v1.19.0.tar.gz' | tar xzf -

EXPOSE 15002

CMD ["php", "-S", "0.0.0.0:15002"]
