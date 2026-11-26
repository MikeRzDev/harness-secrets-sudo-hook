# harness-secrets-sudo-hook build and release. Nothing here runs automatically:
# there is no CI. The command it builds is psudo.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/arm64 darwin/amd64 linux/amd64 linux/arm64

.PHONY: build test dist release formula tap install-claude-code install-codex uninstall-claude-code uninstall-codex install-test-app uninstall-test-app clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/psudo ./cmd/psudo

test:
	go vet ./...
	go test ./...

dist: test
	rm -rf dist
	mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; name=psudo_$(VERSION)_$${os}_$${arch}; \
		mkdir -p dist/$$name; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o dist/$$name/psudo ./cmd/psudo || exit 1; \
		cp LICENSE README.md dist/$$name/; \
		tar -C dist -czf dist/$$name.tar.gz $$name || exit 1; \
		echo "built dist/$$name.tar.gz"; \
	done
	cd dist && shasum -a 256 *.tar.gz > SHA256SUMS

TAP_REPO := MikeRzDev/homebrew-tap
# Releases and the Homebrew formula carry the project's name; the command is psudo.
PROJECT := harness-secrets-sudo-hook
FORMULA := $(PROJECT)

# Publishes a GitHub release from local artifacts, then the Homebrew formula.
# Run only on purpose, from a clean tree:
#   git tag v1.0.0 && git push origin v1.0.0 && make release VERSION=v1.0.0
release: dist formula
	@git diff --quiet HEAD || { echo "release: working tree is dirty"; exit 1; }
	@git rev-parse -q --verify "refs/tags/$(VERSION)" >/dev/null || { echo "release: tag $(VERSION) not found"; exit 1; }
	gh release create $(VERSION) dist/*.tar.gz dist/SHA256SUMS --verify-tag --title "$(PROJECT) $(VERSION)" --generate-notes
	$(MAKE) tap VERSION=$(VERSION)

formula:
	scripts/brew-formula.sh $(VERSION) dist/SHA256SUMS > dist/$(FORMULA).rb

# Pushes the formula to the tap so `brew install MikeRzDev/tap/$(FORMULA)` gets
# it. Formula/psudo.rb is the formula under its earlier name; it is removed.
tap:
	rm -rf dist/tap
	gh repo clone $(TAP_REPO) dist/tap
	mkdir -p dist/tap/Formula
	cp dist/$(FORMULA).rb dist/tap/Formula/$(FORMULA).rb
	cd dist/tap && git rm -q --ignore-unmatch Formula/psudo.rb && git add Formula/$(FORMULA).rb && git commit -m "$(FORMULA) $(VERSION)" && git push

install-claude-code: build
	bin/psudo --install=claude-code

install-codex: build
	bin/psudo --install=codex

uninstall-claude-code: build
	bin/psudo --uninstall=claude-code

uninstall-codex: build
	bin/psudo --uninstall=codex

# macOS, for regression runs only. A test build (tag psudo_testapp, with cgo
# for AppKit) shows its dialogs through /Applications/psudo.app, which
# computer use can answer. It replaces the harness copies with the test build
# and installs the app from the same build; uninstall-test-app removes the app
# and puts normal builds back. Releases never carry the tag.
install-test-app:
	CGO_ENABLED=1 go build -tags psudo_testapp -trimpath -ldflags "$(LDFLAGS)" -o bin/psudo-testapp ./cmd/psudo
	bin/psudo-testapp --install=claude-code
	@if [ -d "$${CODEX_HOME:-$$HOME/.codex}/root-hook" ]; then bin/psudo-testapp --install=codex; fi
	bin/psudo-testapp --install=test-app

uninstall-test-app: build
	bin/psudo --uninstall=test-app
	bin/psudo --install=claude-code
	@if [ -d "$${CODEX_HOME:-$$HOME/.codex}/root-hook" ]; then bin/psudo --install=codex; fi

clean:
	rm -rf bin dist
