.PHONY: help setup rotate-ca-drill backup-drill build run run-lite test lint docker-lite docker-full docker-down install package clean ci ci-rust ci-docs ci-admin ci-trust ci-release-validate

# Default target
help:
	@echo "BSDM-Proxy Automation & Convenience Commands"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  setup         Generate CA certificates for MITM"
	@echo "  rotate-ca-drill  Run an offline CA rotation rehearsal"
	@echo "  backup-drill  CA archive restore + optional ClickHouse backup/restore"
	@echo "  build         Build all workspace members in release mode"
	@echo "  run           Run the proxy locally (default features)"
	@echo "  run-lite      Run the proxy locally (lite mode, no Kafka)"
	@echo "  test          Run all workspace and e2e tests"
	@echo "  lint          Run cargo clippy and rustfmt"
	@echo "  docker-lite   Start the Lite Docker Compose stack (Proxy + SQLite Search API)"
	@echo "  docker-full   Start the Full Docker Compose stack (Kafka, ClickHouse, Prometheus, Grafana)"
	@echo "  docker-down   Stop and remove Docker Compose containers"
	@echo "  install       Run the interactive Linux system installer"
	@echo "  package       Build the Linux release package tarball"
	@echo "  ci            Run the portable Rust, docs, and frontend CI contract"
	@echo "  ci-rust       Run the complete Rust CI gate"
	@echo "  ci-docs       Validate documentation and Wiki mappings"
	@echo "  ci-admin      Validate the Admin Console"
	@echo "  ci-trust      Validate the experimental Trust UI"
	@echo "  ci-release-validate  Validate release metadata without publishing"
	@echo "  clean         Clean Cargo build artifacts"
	@echo ""

setup:
	@echo "Generating MITM CA certificates..."
	./scripts/gen-ca.sh

rotate-ca-drill:
	./scripts/test-ca-rotation.sh

backup-drill:
	./scripts/drill-backup-restore.sh

build:
	cargo build --release --workspace

run:
	HTTP_PORT=3128 METRICS_PORT=9090 MITM_ENABLED=true cargo run -p bsdm-proxy --bin proxy

run-lite:
	HTTP_PORT=3128 METRICS_PORT=9090 MITM_ENABLED=true cargo run -p bsdm-proxy --bin proxy --no-default-features --features auth-basic

test:
	cargo test --workspace

lint:
	cargo fmt --all
	cargo clippy --workspace --all-targets -- -D warnings

docker-lite:
	@if [ ! -f "certs/ca.key" ]; then ./scripts/gen-ca.sh; fi
	docker compose -f deploy/compose/docker-compose.lite.yml up -d --build

docker-full:
	@if [ ! -f "certs/ca.key" ]; then ./scripts/gen-ca.sh; fi
	docker compose up -d --build

docker-down:
	docker compose down
	docker compose -f deploy/compose/docker-compose.lite.yml down

install:
	@echo "Starting interactive installation..."
	@sudo ./scripts/interactive-install.sh

package:
	@echo "Building release package..."
	./scripts/build-package.sh

ci: ci-rust ci-docs ci-admin ci-trust

ci-rust:
	./scripts/ci/run.sh rust-all

ci-docs:
	./scripts/ci/run.sh docs

ci-admin:
	./scripts/ci/run.sh admin-console

ci-trust:
	./scripts/ci/run.sh trust-ui

ci-release-validate:
	./scripts/ci/run.sh release-validate

clean:
	cargo clean
