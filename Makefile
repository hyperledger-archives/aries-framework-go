# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
GO111MODULE=on

.PHONY: all
all: checks unit-test

.PHONY: checks
checks: license lint

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test: generate-test-keys
	@scripts/check_unit.sh

generate-test-keys: clean
	@scripts/openssl_env.sh scripts/generate_test_keys.sh

.PHONY: clean
clean:
	rm -Rf test/fixtures/keys
	rm -f coverage.txt
