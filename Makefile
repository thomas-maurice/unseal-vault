all: build-local

.PHONY := bin
bin:
	if ! [ -d bin ]; then mkdir bin; fi

.PHONY := build-local
build-local: bin
	go build -o bin/unseal-vault

.PHONY := docker-build
docker-build:
	docker build -t mauricethomas/unseal-vault .

.PHONY := load-kind
load-kind:
	kind load docker-image mauricethomas/unseal-vault
