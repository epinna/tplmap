# Running vulnerable test environment in Docker

To setup vulnerable environments for your test, you can use tplmap's test environment with Docker.

The following command starts all test environments:

```sh
$ docker-compose up
```

Starts specified test environments:

```sh
$ docker-compose up tplmap_test_python tplmap_test_php
```

