# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
ARIES_AGENT_REST_PATH=cmd/aries-agent-rest
OPENAPI_DOCKER_IMG=quay.io/goswagger/swagger
OPENAPI_SPEC_PATH=build/rest/openapi/spec
OPENAPI_DOCKER_IMG_VERSION=v0.21.0

# Namespace for the agent images
DOCKER_OUTPUT_NS   ?= aries-framework-go
AGENT_REST_IMAGE_NAME   ?= agent-rest
WEBHOOK_IMAGE_NAME ?= sample-webhook

# Tool commands (overridable)
DOCKER_CMD ?= docker
GO_CMD     ?= go
ALPINE_VER ?= 3.10
GO_TAGS    ?=
GO_VER ?= 1.13.1
PROJECT_ROOT = github.com/hyperledger/aries-framework-go
MOCKGEN = $(shell go env GOPATH)/bin/mockgen

.PHONY: all
all: checks generate-openapi-spec unit-test bdd-test

.PHONY: checks
checks: license lint generate-openapi-spec

.PHONY: lint
lint: mocks
	@scripts/check_lint.sh

.PHONY: license
license:
	@scripts/check_license.sh

.PHONY: unit-test
unit-test: mocks
	@scripts/check_unit.sh

.PHONY: bdd-test
bdd-test: clean generate-test-keys agent-rest-docker sample-webhook-docker
	@scripts/check_integration.sh

.PHONY: vc-test-suite
vc-test-suite: clean
	@scripts/run_vc_test_suite.sh

generate-test-keys: clean
	@mkdir -p -p test/bdd/fixtures/keys/tls
	@docker run -i --rm \
		-v $(abspath .):/opt/go/src/$(PROJECT_ROOT) \
		--entrypoint "/opt/go/src/$(PROJECT_ROOT)/scripts/generate_test_keys.sh" \
		frapsoft/openssl

.PHONY: generate-openapi-spec
generate-openapi-spec: clean
	@echo "Generating and validating controller API specifications using Open API"
	@mkdir -p build/rest/openapi/spec
	@SPEC_META=$(ARIES_AGENT_REST_PATH) SPEC_LOC=${OPENAPI_SPEC_PATH}  \
	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
	scripts/generate-openapi-spec.sh

.PHONY: generate-openapi-demo-specs
generate-openapi-demo-specs: clean generate-openapi-spec agent-rest-docker sample-webhook-docker
	@echo "Generate demo agent rest controller API specifications using Open API"
	@SPEC_PATH=${OPENAPI_SPEC_PATH} OPENAPI_DEMO_PATH=test/bdd/fixtures/demo/openapi \
    	DOCKER_IMAGE=$(OPENAPI_DOCKER_IMG) DOCKER_IMAGE_VERSION=$(OPENAPI_DOCKER_IMG_VERSION)  \
    	scripts/generate-openapi-demo-specs.sh

.PHONY: run-openapi-demo
run-openapi-demo: generate-openapi-demo-specs
	@echo "Starting demo agent rest containers ..."
	@DEMO_COMPOSE_PATH=test/bdd/fixtures/demo/openapi SIDETREE_COMPOSE_PATH=test/bdd/fixtures/sidetree-mock AGENT_REST_COMPOSE_PATH=test/bdd/fixtures/agent-rest  \
        scripts/run-openapi-demo.sh

.PHONY: agent-rest
agent-rest:
	@echo "Building aries-agent-rest"
	@mkdir -p ./build/bin
	@cd ${ARIES_AGENT_REST_PATH} && go build -o ../../build/bin/aries-agent-rest main.go

.PHONY: agent-rest-docker
agent-rest-docker:
	@echo "Building aries agent rest docker image"
	@docker build -f ./images/agent-rest/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(AGENT_REST_IMAGE_NAME):latest \
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
	@docker build -f ./images/mocks/webhook/Dockerfile --no-cache -t $(DOCKER_OUTPUT_NS)/$(WEBHOOK_IMAGE_NAME):latest \
	--build-arg GO_VER=$(GO_VER) \
	--build-arg ALPINE_VER=$(ALPINE_VER) \
	--build-arg GO_TAGS=$(GO_TAGS) \
	--build-arg GOPROXY=$(GOPROXY) .

comma:= ,
semicolon:= ;

define create_mock
  mkdir -p $(1)/mocks && rm -rf $(1)/mocks/*
  $(MOCKGEN) -destination $(1)/mocks/mocks.go -self_package mocks -package mocks $(PROJECT_ROOT)/$(1) $(subst $(semicolon),$(comma),$(2))
endef

build-mockgen:
	go get github.com/golang/mock/mockgen

.PHONY: mocks
mocks: build-mockgen
	$(call create_mock,pkg/client/introduce,Provider)
	$(call create_mock,pkg/didcomm/protocol/introduce,InvitationEnvelope)
	$(call create_mock,pkg/storage,Provider;Store)
	$(call create_mock,pkg/didcomm/common/service,DIDComm)

.PHONY: clean
clean: clean-fixtures clean-build clean-images

.PHONY: clean-images
clean-images: clean-fixtures
clean-images: IMAGES=$(shell docker image ls | grep aries-framework-go | awk '{print $$3}')
clean-images:
	@if [ ! -z "$(IMAGES)" ]; then \
		echo "Cleaning aries-framework-go docker images ..."; \
		docker rmi -f $(IMAGES); \
	fi;

.PHONY: clean-build
clean-build:
	@rm -f coverage.txt
	@rm -Rf ./build
	@rm -Rf ./test/bdd/db
	@rm -Rf ./test/bdd/*.log

.PHONY: clean-fixtures
clean-fixtures:
	@rm -Rf ./test/bdd/fixtures/keys/tls
	@rm -Rf ./test/bdd/fixtures/demo/openapi/specs
	@cd test/bdd/fixtures/agent-rest && docker-compose down 2> /dev/null
	@DEMO_COMPOSE_PATH=test/bdd/fixtures/demo/openapi AGENT_REST_COMPOSE_PATH=test/bdd/fixtures/agent-rest \
        SIDETREE_COMPOSE_PATH=test/bdd/fixtures/sidetree-mock DEMO_COMPOSE_OP=down scripts/run-openapi-demo.sh 2> /dev/null
	@cd test/bdd/fixtures/sidetree-mock && docker-compose down 2> /dev/null
