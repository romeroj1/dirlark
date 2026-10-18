PYTHON ?= python3
.DEFAULT_GOAL := help
.PHONY: help fmt vet lint test build release check check-mac audit deny secrets clean
help:
	@$(PYTHON) tools/public_ci.py help
fmt:
	cargo fmt
vet lint:
	cargo clippy --locked --all-targets -- -D warnings
test:
	cargo test --locked --all-targets
build:
	cargo build --locked
release:
	cargo build --locked --release
check:
	$(PYTHON) tools/public_ci.py check
check-mac:
	$(PYTHON) tools/public_ci.py check-mac
audit:
	cargo audit
deny:
	cargo deny check
secrets:
	$(PYTHON) tools/public_ci.py secrets
clean:
	cargo clean
