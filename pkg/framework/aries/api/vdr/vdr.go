/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"github.com/hyperledger/aries-framework-go/component/vdr/api"
	spivdr "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = api.ErrNotFound

const (
	// DIDCommServiceType default DID Communication service endpoint type.
	DIDCommServiceType = api.DIDCommServiceType

	// DIDCommV2ServiceType is the DID Communications V2 service type.
	DIDCommV2ServiceType = api.DIDCommV2ServiceType

	// LegacyServiceType is the DID Communication V1 indy based service type.
	LegacyServiceType = api.LegacyServiceType
)

// Registry vdr registry.
type Registry = api.Registry

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type VDR = api.VDR

// DIDMethodOpts did method opts.
type DIDMethodOpts = spivdr.DIDMethodOpts

// DIDMethodOption is a did method option.
type DIDMethodOption = spivdr.DIDMethodOption

// WithOption add option for did method.
func WithOption(name string, value interface{}) DIDMethodOption {
	return spivdr.WithOption(name, value)
}
