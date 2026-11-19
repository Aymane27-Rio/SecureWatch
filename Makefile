SHELL := /bin/bash
PY := python3
VENV := .venv
PIP := $(VENV)/bin/pip
PYTHON := $(VENV)/bin/python

.PHONY: help install-deps venv cli run report exporter test package-deb package-rpm enable-systemd clean

help:
	@echo "Targets:"
	@echo "  install-deps   - Install system packages via apt, dnf, zypper, or pacman"
	@echo "  venv           - Create Python venv and install requirements"
	@echo "  cli            - Show SecureWatch command help"
	@echo "  run            - Run SecureWatch one-off scan"
	@echo "  report         - Render the latest scan as HTML"
	@echo "  exporter       - Run Prometheus exporter on :9109"
	@echo "  test           - Run the deterministic unit test suite"
	@echo "  package-deb    - Build a Debian package (VERSION=... OUTPUT=dist)"
	@echo "  package-rpm    - Build a Fedora RPM (requires rpmbuild)"
	@echo "  enable-systemd - Install and enable systemd timer (hourly)"
	@echo "  clean          - Remove venv and generated artifacts"

install-deps:
	bash scripts/install.sh

venv:
	test -d $(VENV) || $(PY) -m venv $(VENV)
	$(PIP) install --upgrade pip
	$(PIP) install -r python/requirements.txt -r webapi/requirements.txt

cli:
	python3 bin/securewatch --help

run:
	python3 bin/securewatch scan

report:
	python3 bin/securewatch report

exporter:
	$(PYTHON) python/exporters/securewatch_exporter.py

test:
	$(PYTHON) -m unittest discover -s tests -v

VERSION ?= $(shell cat VERSION)
OUTPUT ?= dist

package-deb:
	bash packaging/build-deb.sh "$(VERSION)" "$(OUTPUT)"

package-rpm:
	bash packaging/build-rpm.sh "$(VERSION)" "$(OUTPUT)"

enable-systemd:
	@echo "This target requires the SecureWatch system package to be installed."
	@sudo systemctl daemon-reload
	@sudo systemctl enable --now securewatch.timer

clean:
	rm -rf $(VENV) data/reports/*.html data/logs/*.json data/logs/*.ndjson dist || true
