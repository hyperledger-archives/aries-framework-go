# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
# Controller API entry point to be used for generating Open API specifications
OPENAPI_SPEC_META=cmd/aries-agentd/main.go
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_DOCKER_IMG_VERSION=v0.20.1

.PHONY: all
all: checks generate-openapi-spec unit-test bdd-test

.PHONY: checks
checks: license lint generate-openapi-spec

.PHONY: lint
lint:
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test:
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: clean
	@scripts/check_integration.sh

.PHONY: vc-test-suite
vc-test-suite: clean
	@scripts/run_vc_test_suite.sh

.PHONY: clean
clean:
	rm -f coverage.txt
	rm -Rf ./build
	rm -Rf ./test/bdd/db

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p build/rest/openapi/spec
	@SPEC_META=$(OPENAPI_SPEC_META) SPEC_LOC=build/rest/openapi/spec  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh
