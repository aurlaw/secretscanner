BINARY     := secretscanner
MODULE     := github.com/aurlaw/secretscanner
CMD        := ./cmd/secretscanner

VERSION    := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT     := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
LDFLAGS    := -ldflags "-X $(MODULE)/internal/version.Version=$(VERSION) \
                         -X $(MODULE)/internal/version.Commit=$(COMMIT)"

.PHONY: build test lint clean

build:
	go build $(LDFLAGS) -o $(BINARY) $(CMD)

test:
	go test -race ./...

lint:
	go vet ./...

clean:
	rm -f $(BINARY)