PREFIX  ?= $(HOME)/.local
VERSION := $(shell cat VERSION)
LDFLAGS := -s -w -X github.com/orchard-suite/tender/internal/cli.Version=$(VERSION)

.PHONY: install build test check land

# The default: build tender and install it. When this user's service is
# installed, it is installed again, so it runs the new build.
install: build
	mkdir -p "$(PREFIX)/bin"
	install -m 0755 dist/tender "$(PREFIX)/bin/tender"
	@if [ -f "$(HOME)/Library/LaunchAgents/io.github.orchard-suite.tender.plist" ] || \
	    [ -f "$(HOME)/.config/systemd/user/tender.service" ]; then \
		"$(PREFIX)/bin/tender" install; \
	fi

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/tender ./cmd/tender

test:
	go test ./...

# Every operating system's code is vetted from any one of them.
check:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "run gofmt -w ." >&2; exit 1; }
	go vet ./...
	GOOS=linux go vet ./...
	GOOS=windows go vet ./...
	go test ./...

land: check
	release-damnit land $(BRANCH)
