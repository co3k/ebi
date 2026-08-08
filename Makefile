.PHONY: all build test lint clean cross-build cross-clean

BINARIES := ebi ebi-server ebi-monitor

all: build test

build:
	GOTOOLCHAIN=local CGO_ENABLED=0 go build ./cmd/...

test:
	GOTOOLCHAIN=local go test ./...

lint:
	GOTOOLCHAIN=local go vet ./...
	@test -z "$$(find cmd internal pkg -name '*.go' -type f -print0 | xargs -0 gofmt -l)"

cross-build:
	mkdir -p dist
	@set -eu; \
	for bin in $(BINARIES); do \
	  for target in darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64; do \
	    os=$${target%/*}; arch=$${target#*/}; ext=""; \
	    if [ "$$os" = windows ]; then ext=".exe"; fi; \
	    echo "building $$bin for $$os/$$arch"; \
	    GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	      go build -trimpath -o "dist/$$bin-$$os-$$arch$$ext" "./cmd/$$bin"; \
	  done; \
	done

cross-clean:
	rm -rf dist/

clean: cross-clean

.DEFAULT_GOAL := all
