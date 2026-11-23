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

# On a Mac with a Developer ID, the build is signed the way a release is, so
# the keychain keeps trusting it with the device key.
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o dist/tender ./cmd/tender
	@if [ "$$(uname)" = Darwin ]; then \
		id=$$(security find-identity -v -p codesigning 2>/dev/null | awk '/Developer ID Application/ {print $$2; exit}'); \
		if [ -n "$$id" ]; then codesign --force --timestamp --identifier io.github.orchard-suite.tender --sign "$$id" dist/tender; fi; \
	fi

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
