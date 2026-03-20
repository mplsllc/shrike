.PHONY: build server crawler rir-import bgp-import zone-import export ct-import cc-import wayback-import clean test vet

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X git.mp.ls/mpls/shrike/internal/version.Version=$(VERSION)"

build: server crawler rir-import bgp-import zone-import export ct-import cc-import wayback-import

server:
	go build $(LDFLAGS) -o shrike-server ./cmd/server

crawler:
	go build $(LDFLAGS) -o shrike-crawler ./cmd/crawler

rir-import:
	go build $(LDFLAGS) -o shrike-rir-import ./cmd/rir-import

bgp-import:
	go build $(LDFLAGS) -o shrike-bgp-import ./cmd/bgp-import

zone-import:
	go build $(LDFLAGS) -o shrike-zone-import ./cmd/zone-import

export:
	go build $(LDFLAGS) -o shrike-export ./cmd/export

ct-import:
	go build $(LDFLAGS) -o shrike-ct-import ./cmd/ct-import

cc-import:
	go build $(LDFLAGS) -o shrike-cc-import ./cmd/cc-import

wayback-import:
	go build $(LDFLAGS) -o shrike-wayback-import ./cmd/wayback-import

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f shrike-server shrike-crawler shrike-rir-import shrike-bgp-import shrike-zone-import shrike-export shrike-ct-import shrike-cc-import shrike-wayback-import

migrate:
	@echo "Run migrations against DATABASE_URL"
	@for f in internal/db/migrations/*.sql; do \
		echo "Applying $$f..."; \
		psql "$(DATABASE_URL)" -f "$$f"; \
	done
