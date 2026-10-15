ROCKCRAFT_YAML ?= rockcraft.yaml
GO_SERVER_BUILD_DIR ?= .build/go-server
TRIVY_SEVERITY ?= HIGH,CRITICAL
TRIVY_SKIP_FILES ?= /bin/pebble,/usr/bin/pebble
ROCK_FILE ?= $(firstword $(wildcard authentik-server_*.rock))

.PHONY: govulncheck scan-rock test clean

govulncheck:
	@if [ "$$(yq '.parts | has("go-server")' $(ROCKCRAFT_YAML))" = "true" ]; then \
		set -e; \
		go_source=$$(yq -r '.parts.go-server.source' $(ROCKCRAFT_YAML)); \
		go_tag=$$(yq -r '.parts.go-server."source-tag"' $(ROCKCRAFT_YAML)); \
		rm -rf $(GO_SERVER_BUILD_DIR); \
		mkdir -p $(dir $(GO_SERVER_BUILD_DIR)); \
		git clone --depth 1 --branch "$$go_tag" "$$go_source" $(GO_SERVER_BUILD_DIR); \
		cd $(GO_SERVER_BUILD_DIR); \
		export GOTOOLCHAIN=auto; \
		yq -r '.parts.go-server."override-build"' $(abspath $(ROCKCRAFT_YAML)) | grep -E '^\s*go (get|mod)\b' | sh -ex; \
		GOBIN="$$(pwd)/.bin" go install golang.org/x/vuln/cmd/govulncheck@latest; \
		"$$(pwd)/.bin/govulncheck" ./...; \
	else \
		echo "No go-server part in $(ROCKCRAFT_YAML). Skip govulncheck."; \
	fi

scan-rock:
	@if [ -z "$(ROCK_FILE)" ]; then \
		echo "Error: No rock file found. Run 'rockcraft pack' or set ROCK_FILE=<path>."; \
		exit 1; \
	fi
	trivy image \
		--input "$(ROCK_FILE)" \
		--severity "$(TRIVY_SEVERITY)" \
		--ignore-unfixed \
		--ignorefile .trivyignore \
		--skip-files "$(TRIVY_SKIP_FILES)" \
		--exit-code 1

test:
	python3 -m unittest discover -s tests -v

clean:
	rm -rf .build
