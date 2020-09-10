// Copyright SecureKey Technologies Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

module github.com/hyperledger/aries-framework-go/test/bdd

go 1.15

require (
	github.com/Microsoft/hcsshim v0.8.7 // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v1.0.1
	github.com/containerd/containerd v1.3.3 // indirect
	github.com/containerd/continuity v0.0.0-20200107194136-26c1120b8d41 // indirect
	github.com/cucumber/godog v0.8.1
	github.com/evanphx/json-patch v4.5.0+incompatible // indirect
	github.com/fsouza/go-dockerclient v1.6.1
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/google/uuid v1.1.1
	github.com/gorilla/mux v1.7.3
	github.com/hyperledger/aries-framework-go v0.0.0
	github.com/konsorten/go-windows-terminal-sequences v1.0.2 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/piprate/json-gold v0.3.0
	github.com/trustbloc/sidetree-core-go v0.1.4-0.20200818145448-94243b40fa44
	golang.org/x/net v0.0.0-20200625001655-4c5254603344
	google.golang.org/genproto v0.0.0-20200211111953-2dc5924e3898 // indirect
	google.golang.org/grpc v1.27.1 // indirect
	nhooyr.io/websocket v1.8.3
)

replace github.com/hyperledger/aries-framework-go => ../..
