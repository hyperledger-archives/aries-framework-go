/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vdr

import (
	"errors"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/deactivate"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/recovery"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/resolve"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/update"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("DID not found")

// DIDCommServiceType default DID Communication service endpoint type.
const DIDCommServiceType = "did-communication"

// Registry vdr registry.
type Registry interface {
	Resolve(did string, opts ...resolve.Option) (*did.DocResolution, error)
	Store(doc *did.Doc) error
	Create(method string, opts ...create.Option) (*did.DocResolution, error)
	Update(did string, opts ...update.Option) error
	Recover(did string, opts ...recovery.Option) error
	Deactivate(did string, opts ...deactivate.Option) error
	Close() error
}

// VDR verifiable data registry interface.
type VDR interface {
	Read(did string, opts ...resolve.Option) (*did.DocResolution, error)
	Store(doc *did.Doc, by *[]doc.ModifiedBy) error
	Build(keyManager kms.KeyManager, opts ...create.Option) (*did.DocResolution, error)
	Update(did string, opts ...update.Option) error
	Recover(did string, opts ...recovery.Option) error
	Deactivate(did string, opts ...deactivate.Option) error
	Accept(method string) bool
	Close() error
}
