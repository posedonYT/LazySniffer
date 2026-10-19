GO      ?= go
BIN     ?= bin/lazysniffer
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/poseydon/lazysniffer/internal/version.Version=$(VERSION)

.PHONY: build run test race fuzz vet lint generate difftest clean release-check

build:
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN) ./cmd/lazysniffer

run: build
	./$(BIN) $(ARGS)

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

# Short fuzzing pass over every parser that reads untrusted input.
fuzz:
	$(GO) test -run=^$$ -fuzz=FuzzOpen -fuzztime=30s ./internal/pcapio/
	$(GO) test -run=^$$ -fuzz=FuzzCompile -fuzztime=30s ./internal/dfilter/
	$(GO) test -run=^$$ -fuzz=FuzzDissect -fuzztime=60s ./internal/dissect/proto/
	$(GO) test -run=^$$ -fuzz=FuzzApps -fuzztime=60s ./internal/dissect/proto/

# Compare with a real tshark (needs Wireshark's command line tools).
difftest:
	$(GO) test -count=1 -v ./internal/difftest/ ./internal/lua/ ./internal/pcaptools/ ./internal/deep/ | grep -E '^(---|ok|FAIL|PASS)'

release-check:
	goreleaser check

# Regenerate the embedded IEEE OUI and IANA service tables.
generate:
	$(GO) generate ./internal/resolve/

clean:
	rm -rf bin
