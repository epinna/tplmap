FROM ruby:latest

RUN gem install slim tilt cuba rack
RUN apt-get update && apt-get install dnsutils -y

WORKDIR /tests
COPY tests/env_ruby_tests .

EXPOSE 15005

CMD ["rackup", "--host", "0.0.0.0", "--port", "15005"]
