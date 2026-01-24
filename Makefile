# Syfter Build Makefile
#
# Usage:
#   make build                    # Build with current version
#   make build VERSION=1.0.0      # Build with new version (updates all files first)
#   make publish VERSION=1.0.0    # Update version, build, and publish to PyPI
#   make tag VERSION=1.0.0        # Create and push a git tag
#   make release VERSION=1.0.0    # Full release: version bump, build, publish, tag
#
# Other targets:
#   make clean                    # Remove build artifacts
#   make test                     # Run tests
#   make check                    # Run linters
#   make version                  # Show current version

SHELL := /bin/bash

# Get current version from pyproject.toml
CURRENT_VERSION := $(shell grep -m1 '^version' pyproject.toml | cut -d'"' -f2)

# Files that contain the version string
VERSION_FILES := \
	pyproject.toml \
	syfter/__init__.py \
	server/__init__.py \
	server/main.py \
	README.md \
	docs/BUILDING.md

.PHONY: all build publish clean test check version set-version tag release help

# Default target
all: build

# Show current version
version:
	@echo "Current version: $(CURRENT_VERSION)"

# Update version in all files
# Usage: make set-version VERSION=1.0.0
set-version:
ifndef VERSION
	$(error VERSION is not set. Usage: make set-version VERSION=1.0.0)
endif
	@echo "Updating version from $(CURRENT_VERSION) to $(VERSION)..."
	@# pyproject.toml: version = "X.Y.Z"
	@sed -i.bak 's/^version = ".*"/version = "$(VERSION)"/' pyproject.toml
	@# syfter/__init__.py: __version__ = "X.Y.Z"
	@sed -i.bak 's/__version__ = ".*"/__version__ = "$(VERSION)"/' syfter/__init__.py
	@# server/__init__.py: __version__ = "X.Y.Z"
	@sed -i.bak 's/__version__ = ".*"/__version__ = "$(VERSION)"/' server/__init__.py
	@# server/main.py: __version__ = "X.Y.Z"
	@sed -i.bak 's/__version__ = ".*"/__version__ = "$(VERSION)"/' server/main.py
	@# README.md: **Version: X.Y.Z**
	@sed -i.bak 's/\*\*Version: .*\*\*/\*\*Version: $(VERSION)\*\*/' README.md
	@# docs/BUILDING.md: Current version: **X.Y.Z**
	@sed -i.bak 's/Current version: \*\*.*\*\*/Current version: \*\*$(VERSION)\*\*/' docs/BUILDING.md
	@# Clean up backup files created by sed -i
	@rm -f pyproject.toml.bak syfter/__init__.py.bak server/__init__.py.bak server/main.py.bak README.md.bak docs/BUILDING.md.bak
	@echo "Version updated to $(VERSION) in all files."

# Build the package
# If VERSION is specified, update version first
build:
ifdef VERSION
	@$(MAKE) set-version VERSION=$(VERSION)
endif
	@echo "Building syfter..."
	@rm -rf dist/
	uv build
	@echo "Build complete. Artifacts in dist/"
	@ls -la dist/

# Publish to PyPI
# If VERSION is specified, update version and build first
publish:
ifdef VERSION
	@$(MAKE) set-version VERSION=$(VERSION)
endif
	@echo "Building and publishing to PyPI..."
	@rm -rf dist/
	uv build
	uv publish
	@echo "Published version $$(grep -m1 '^version' pyproject.toml | cut -d'\"' -f2) to PyPI"

# Create and push git tag
tag:
ifndef VERSION
	VERSION := $(CURRENT_VERSION)
endif
	@echo "Creating git tag v$(VERSION)..."
	git tag -a "v$(VERSION)" -m "Release $(VERSION)"
	@echo "Pushing tag to origin..."
	git push origin "v$(VERSION)"
	@echo "Tag v$(VERSION) created and pushed."

# Full release: update version, build, publish, and tag
release:
ifndef VERSION
	$(error VERSION is not set. Usage: make release VERSION=1.0.0)
endif
	@echo "=== Starting release $(VERSION) ==="
	@$(MAKE) set-version VERSION=$(VERSION)
	@echo ""
	@echo "=== Building ==="
	@rm -rf dist/
	uv build
	@echo ""
	@echo "=== Publishing to PyPI ==="
	uv publish
	@echo ""
	@echo "=== Creating git tag ==="
	git add pyproject.toml syfter/__init__.py server/__init__.py server/main.py README.md docs/BUILDING.md
	git commit -m "Release $(VERSION)"
	git tag -a "v$(VERSION)" -m "Release $(VERSION)"
	git push origin HEAD
	git push origin "v$(VERSION)"
	@echo ""
	@echo "=== Release $(VERSION) complete ==="

# Clean build artifacts
clean:
	rm -rf dist/
	rm -rf build/
	rm -rf *.egg-info/
	rm -rf syfter.egg-info/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@echo "Cleaned build artifacts."

# Run tests
test:
	./scripts/run-tests.sh local

# Run tests with coverage
coverage:
	./scripts/run-tests.sh coverage

# Run linters
check:
	@echo "Running ruff..."
	uv run ruff check syfter/ server/
	@echo "Running black check..."
	uv run black --check syfter/ server/

# Format code
format:
	uv run ruff check --fix syfter/ server/
	uv run black syfter/ server/

# Install for development
dev:
	uv pip install -e ".[all]"

# Show help
help:
	@echo "Syfter Build System"
	@echo ""
	@echo "Version Management:"
	@echo "  make version                  Show current version"
	@echo "  make set-version VERSION=X.Y.Z   Update version in all files"
	@echo ""
	@echo "Building:"
	@echo "  make build                    Build with current version"
	@echo "  make build VERSION=X.Y.Z      Update version then build"
	@echo "  make clean                    Remove build artifacts"
	@echo ""
	@echo "Publishing:"
	@echo "  make publish                  Build and publish current version"
	@echo "  make publish VERSION=X.Y.Z    Update version, build, and publish"
	@echo "  make tag VERSION=X.Y.Z        Create and push git tag"
	@echo "  make release VERSION=X.Y.Z    Full release (version + build + publish + tag)"
	@echo ""
	@echo "Development:"
	@echo "  make dev                      Install in development mode"
	@echo "  make test                     Run tests"
	@echo "  make coverage                 Run tests with coverage"
	@echo "  make check                    Run linters"
	@echo "  make format                   Auto-format code"
