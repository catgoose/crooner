.DEFAULT_GOAL := help

.PHONY: help build test generate-error-examples verify-docs ci install-playwright pkce-sim

help:
	@echo "Targets:"
	@echo "  build                 Build bin/oauth-server, bin/app, bin/simulate"
	@echo "  test                  Run go test ./..."
	@echo "  generate-error-examples  Generate docs/error-examples/*.json and update docs/errors.md"
	@echo "  verify-docs           Fail if docs/ has uncommitted changes"
	@echo "  ci                    build, test, generate-error-examples, verify-docs"
	@echo "  install-playwright    Install Playwright browsers for simulate"
	@echo "  pkce-sim              Run PKCE simulation (depends on build)"

build:
	mkdir -p bin
	go build -v -o bin/oauth-server ./cmd/oauth-server/
	go build -v -o bin/app ./cmd/app/
	cd simulate && go build -v -o ../bin/simulate .

test:
	go test -v ./...

generate-error-examples:
	./scripts/gen-error-examples.sh

verify-docs:
	git diff --exit-code docs/

ci: build test generate-error-examples verify-docs

install-playwright:
	cd simulate && go run github.com/playwright-community/playwright-go/cmd/playwright install --with-deps

pkce-sim: build
	SKIP_BUILD=1 ./scripts/run-pkce-sim.sh
