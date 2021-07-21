/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID not found")

// DIDCommServiceType default DID Communication V1 service endpoint type.
const DIDCommServiceType = "did-communication"

// DIDCommV2ServiceType is the DID Communication V2 service type as per the following ref:
// https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint.
const DIDCommV2ServiceType = "DIDCommMessaging"

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...DIDMethodOption) (*did.DocResolution, error)
	Create(method string, did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type VDR interface {
	Read(did string, opts ...DIDMethodOption) (*did.DocResolution, error)
	Create(did *did.Doc, opts ...DIDMethodOption) (*did.DocResolution, error)
	Accept(method string) bool
	Update(did *did.Doc, opts ...DIDMethodOption) error
	Deactivate(did string, opts ...DIDMethodOption) error
	Close() error
}

// DIDMethodOpts did method opts.
type DIDMethodOpts struct {
	Values map[string]interface{}
}

// DIDMethodOption is a did method option.
type DIDMethodOption func(opts *DIDMethodOpts)

// WithOption add option for did method.
func WithOption(name string, value interface{}) DIDMethodOption {
	return func(didMethodOpts *DIDMethodOpts) {
		didMethodOpts.Values[name] = value
	}
}
