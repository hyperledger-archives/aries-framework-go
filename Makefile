# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

GO_CMD ?= go
ARIES_AGENT_REST_PATH=cmd/aries-agent-rest
ARIES_JS_WORKER_WASM_PATH=cmd/aries-js-worker
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
GOBIN_PATH=$(abspath .)/build/bin
MOCKGEN = $(GOBIN_PATH)/gobin -run github.com/golang/mock/mockgen@1.3.1
GOMOCKS=pkg/internal/gomocks

.PHONY: all
all: clean checks unit-test unit-test-wasm bdd-test

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

.PHONY: unit-test-wasm
unit-test-wasm: export GOBIN=$(GOBIN_PATH)
unit-test-wasm: depend
	@scripts/check_unit_wasm.sh

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
run-openapi-demo: generate-test-keys generate-openapi-demo-specs
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
mocks_dir =

define create_mock
  $(eval mocks_dir := $(subst pkg,$(GOMOCKS),$(1)))
  @echo Creating $(mocks_dir)
  @mkdir -p $(mocks_dir) && rm -rf $(mocks_dir)/*
  @$(MOCKGEN) -destination $(mocks_dir)/mocks.go -self_package mocks -package mocks $(PROJECT_ROOT)/$(1) $(subst $(semicolon),$(comma),$(2))
endef

depend:
	@mkdir -p ./build/bin
	@GO111MODULE=off GOBIN=$(GOBIN_PATH) go get github.com/myitcv/gobin
	@GO111MODULE=off GOBIN=$(GOBIN_PATH) go get github.com/agnivade/wasmbrowsertest

.PHONY: mocks
mocks: depend
	$(call create_mock,pkg/client/introduce,Provider)
	$(call create_mock,pkg/didcomm/protocol/introduce,Provider;InvitationEnvelope)
	$(call create_mock,pkg/didcomm/common/service,DIDComm;Event;Messenger;MessengerHandler)
	$(call create_mock,pkg/didcomm/dispatcher,Outbound)
	$(call create_mock,pkg/storage,Provider;Store)
	$(call create_mock,pkg/didcomm/messenger,Provider)

.PHONY: clean-mocks
clean-mocks:
	@if [ -d $(GOMOCKS) ]; then rm -r $(GOMOCKS); echo "Folder $(GOMOCKS) was removed!"; fi

.PHONY: clean
clean: clean-fixtures clean-build clean-images clean-mocks

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
	@cd test/bdd/fixtures/demo/openapi && docker-compose down 2> /dev/null
	@cd test/bdd/fixtures/sidetree-mock && docker-compose down 2> /dev/null
	@cd test/bdd/fixtures/agent-rest && docker-compose down 2> /dev/null

