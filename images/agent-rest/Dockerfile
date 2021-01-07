#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

ARG GO_VER
ARG ALPINE_VER

FROM golang:${GO_VER}-alpine${ALPINE_VER} as golang
RUN apk add --no-cache \
	gcc \
	musl-dev \
	git \
	libtool \
	bash \
	make;
ADD . $GOPATH/src/github.com/hyperledger/aries-framework-go
WORKDIR $GOPATH/src/github.com/hyperledger/aries-framework-go
ENV EXECUTABLES go git

FROM golang as aries-framework
LABEL org.opencontainers.image.source https://github.com/hyperledger/aries-framework-go

ARG GO_TAGS
ARG GOPROXY
RUN GO_TAGS=${GO_TAGS} GOPROXY=${GOPROXY} make agent-rest


FROM alpine:${ALPINE_VER} as base
RUN apk add -U --no-cache ca-certificates
COPY --from=aries-framework /go/src/github.com/hyperledger/aries-framework-go/build/bin/aries-agent-rest /usr/local/bin
ENTRYPOINT ["aries-agent-rest"]
