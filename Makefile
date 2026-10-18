.PHONY: build test

build:
	go build -o sekidp-ctk ./cmd/sekidp-ctk

test:
	go test ./...
