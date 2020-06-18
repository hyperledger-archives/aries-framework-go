# Copyright SecureKey Technologies Inc.
#
# SPDX-License-Identifier: Apache-2.0

MAKEFILE_DIR := ${CURDIR}

GO_CMD ?= go
GOMOBILE_CMD ?= gomobile

PROJECT_ROOT = github.com/hyperledger/aries-framework-go
# TODO change this to cmd/aries-agent-mobile/
# when https://github.com/hyperledger/aries-framework-go/issues/1923 is ready
MOBILE_BINDINGS_ROOT_PACKAGE := $(PROJECT_ROOT)/pkg/didcomm/transport/ws
BUILD_DIR = $(MAKEFILE_DIR)/build

ANDROID_BUILD_DIR = $(BUILD_DIR)/android
ANDROID_OUTPUT_FILE_NAME = aries-agent-mobile.aar
ifeq ($(ANDROID_TARGET),)
	ANDROID_TARGET = android
endif

IOS_BUILD_DIR = $(BUILD_DIR)/ios
IOS_OUTPUT_FILE_NAME = AriesAgentMobile.framework
ifeq ($(IOS_TARGET),)
    IOS_TARGET = ios
endif

help:
	@echo 'Commands:'
	@$(MAKE) -pRrq -f $(lastword $(MAKEFILE_LIST)) : 2>/dev/null \
		| awk -v RS= -F: '/^# File/,/^# Finished Make data base/ {if ($$1 !~ "^[#.]") {print $$1}}' \
		| sort \
		| egrep -v -e '^[^[:alnum:]]' -e '^$@$$' \
		| grep -v / \
		| sed 's/^/	$(HELP_MSG_PREFIX)make /'

.PHONY: all
all: clean dependencies bindings

.PHONY: clean
clean: clean-android clean-ios
	@rm -Rf $(BUILD_DIR)

.PHONY: clean-android
clean-android:
	@rm -Rf $(ANDROID_BUILD_DIR)

.PHONY: clean-ios
clean-ios:
	@rm -Rf $(IOS_BUILD_DIR)

.PHONY: dependencies
dependencies:
	@echo '----------------------------------------'
	@echo '   Installing dependencies              '
	@echo '----------------------------------------'
	@GO111MODULE=off go get golang.org/x/mobile/cmd/gomobile
	$(GOMOBILE_CMD) init -v

.PHONY: bindings
bindings: bindings-android bindings-ios

.PHONY: bindings-android
bindings-android:
	@echo '----------------------------------------'
	@echo '   gomobile: Creating Android bindings  '
	@echo '----------------------------------------'
	@mkdir -p $(ANDROID_BUILD_DIR)
	$(GOMOBILE_CMD) bind -v -target=$(ANDROID_TARGET) -o=$(ANDROID_BUILD_DIR)/$(ANDROID_OUTPUT_FILE_NAME) $(MOBILE_BINDINGS_ROOT_PACKAGE)

.PHONY: bindings-ios
bindings-ios:
	@echo '----------------------------------------'
	@echo '   gomobile: Creating iOS bindings      '
	@echo '----------------------------------------'
	@mkdir -p $(IOS_BUILD_DIR)
	$(GOMOBILE_CMD) bind -v -target=$(IOS_TARGET) -o=$(IOS_BUILD_DIR)/$(IOS_OUTPUT_FILE_NAME) $(MOBILE_BINDINGS_ROOT_PACKAGE)

