/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	spivdr "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID does not exist")

const (
	// DIDCommServiceType default DID Communication service endpoint type.
	DIDCommServiceType = "did-communication"

	// DIDCommV2ServiceType is the DID Communications V2 service type.
	DIDCommV2ServiceType = "DIDCommMessaging"

	// LegacyServiceType is the DID Communication V1 indy based service type.
	LegacyServiceType = "IndyAgent"
)

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Create(method string, did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Update(did *did.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type VDR interface {
	Read(did string, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Create(did *did.Doc, opts ...spivdr.DIDMethodOption) (*did.DocResolution, error)
	Accept(method string, opts ...spivdr.DIDMethodOption) bool
	Update(did *did.Doc, opts ...spivdr.DIDMethodOption) error
	Deactivate(did string, opts ...spivdr.DIDMethodOption) error
	Close() error
}

// DIDMethodOpts did method opts.
type DIDMethodOpts = spivdr.DIDMethodOpts

// DIDMethodOption is a did method option.
type DIDMethodOption = spivdr.DIDMethodOption

// WithOption add option for did method.
func WithOption(name string, value interface{}) DIDMethodOption {
	return spivdr.WithOption(name, value)
}
