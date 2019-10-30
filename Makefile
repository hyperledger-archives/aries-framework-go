# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
ARIES_AGENTD_MAIN=cmd/aries-agentd/main.go
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=build/rest/openapi/spec
# TODO: Switched to dev since release version doesn't support go 1.13
OPENAPI_DOCKER_IMG_VERSION=dev

# Namespace for the agent images
DOCKER_OUTPUT_NS  ?= aries-framework-go
AGENT_IMAGE_NAME  ?= agent

# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.10
GO_TAGS    ?=
GO_VER ?= 1.13.1

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
bdd-test: clean generate-test-keys agent-docker sample-webhook-docker
	@scripts/check_integration.sh

.PHONY: vc-test-suite
vc-test-suite: clean
	@scripts/run_vc_test_suite.sh

.PHONY: clean
clean:
	rm -f coverage.txt
	rm -Rf ./build
	rm -Rf ./test/bdd/db
	rm -Rf ./test/bdd/fixtures/keys/tls
	rm -Rf ./test/bdd/fixtures/demo/openapi/specs
	rm -Rf ./test/bdd/*.log

generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/go/src/github.com/hyperledger/aries-framework-go \
		--entrypoint "/opt/go/src/github.com/hyperledger/aries-framework-go/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p build/rest/openapi/spec
	@SPEC_META=$(ARIES_AGENTD_MAIN) SPEC_LOC=${OPENAPI_SPEC_PATH}  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-demo-specs
generate-openapi-demo-specs: clean generate-openapi-spec agent-docker
	@echo "Generate demo agent controller API specifications using Open API"
	@SPEC_PATH=${OPENAPI_SPEC_PATH} OPENAPI_DEMO_PATH=test/bdd/fixtures/demo/openapi \
    	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
    	scripts/generate-openapi-demo-specs.sh

.PHONY: run-openapi-demo
run-openapi-demo: generate-openapi-demo-specs
	@echo "Starting demo agent containers"
	@DEMO_COMPOSE_PATH=test/bdd/fixtures/demo/openapi AGENT_COMPOSE_PATH=test/bdd/fixtures/agent  \
        scripts/run_openapi_demo.sh

.PHONY: agent
agent:
	@echo "Building aries-agentd"
	@mkdir -p ./build/bin
	@go build -o ./build/bin/aries-agentd ${ARIES_AGENTD_MAIN}

.PHONY: agent-docker
agent-docker:
	@echo "Building aries agent docker image"
	@docker build -f ./images/agent/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(AGENT_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

.PHONY: sample-webhook
sample-webhook:
	@echo "Building sample webhook server"
	@mkdir -p ./build/bin
	@go build -o ./build/bin/webhook-server test/bdd/webhook/main.go

.PHONY: sample-webhook-docker
sample-webhook-docker:
	@echo "Building sample webhook server docker image"
	@docker build -f ./images/mocks/webhook/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/sample-webhook:latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .