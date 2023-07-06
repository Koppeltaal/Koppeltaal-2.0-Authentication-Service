# Koppeltaal-2.0-Authentication-Service 

## Building docker
```shell
docker build . -t koppeltaal-2.0-authentication-service
```

## Project setup
### Install the dependencies
```shell
poetry install
```
### Update to the latest dependencies (will change the [poetry.lock](poetry.lock) file).
```shell
poetry update
```
### Add an dependency
```shell
poetry add [dep-name]
```
### Add a test dependency
```shell
poetry add [dep-name] --group test
```
### Running the app
```shell
poetry run python3 entrypoint.py
```
