/*
Copyright Gen Digital Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/vdr/peer"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	// StoreNamespace store name space for DID Store.
	StoreNamespace = "peer"
	// DefaultServiceType default service type.
	DefaultServiceType = "defaultServiceType"
	// DefaultServiceEndpoint default service endpoint.
	DefaultServiceEndpoint = "defaultServiceEndpoint"
	// DIDMethod is the peer did method name: https://identity.foundation/peer-did-method-spec/#method-name.
	DIDMethod = "peer"
)

// VDR implements building new peer dids.
type VDR = peer.VDR

// New return new instance of peer vdr.
func New(s storage.Provider) (*VDR, error) {
	return peer.New(s)
}

// NewDoc returns the resolved variant of the genesis version of the peer DID document.
func NewDoc(publicKey []did.VerificationMethod, opts ...did.DocOption) (*did.Doc, error) {
	return peer.NewDoc(publicKey, opts...)
}

// UnsignedGenesisDelta returns a marshaled and base64-encoded json array containing a single peer DID delta
// for the given doc.
func UnsignedGenesisDelta(doc *did.Doc) (string, error) {
	return peer.UnsignedGenesisDelta(doc)
}

// DocFromGenesisDelta parses a marshaled genesis delta, returning the doc contained within.
func DocFromGenesisDelta(initialState string) (*did.Doc, error) {
	return peer.DocFromGenesisDelta(initialState)
}
