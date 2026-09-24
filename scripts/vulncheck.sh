#!/usr/bin/env bash
# The vulnerability check: govulncheck's JSON stream over the module
# judged against the standing exceptions (vulncheck.exceptions) by
# internal/vulnexcept. One spelling, run by the workflow and the
# Taskfile alike.
set -euo pipefail
cd "$(dirname "$0")/.."
go run golang.org/x/vuln/cmd/govulncheck@latest -format json ./... \
  | go run ./internal/vulnexcept -exceptions vulncheck.exceptions
