VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT 	?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE 	?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BINARY 	:= sift
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)

.PHONY: build clean test lint tidy all install go-install fmt run

build:
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) .

clean:
	rm -f $(BINARY)

test:
	go test ./...

lint:
	go vet ./...

tidy:
	go mod tidy

install: build
	cp $(BINARY) $(HOME)/.local/bin/$(BINARY)

go-install:
	go install -ldflags "$(LDFLAGS)" .

fmt:
	gofmt -w .

run:
	go run -ldflags "$(LDFLAGS)" . $(ARGS)

all: tidy lint test build