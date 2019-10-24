/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package operator

import (
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// CryptoOperator denotes an object that accesses keys in a KeyHolder
//
// Framework CryptoOperators are defined in this package or subpackages.
// Clients who need to define their own crypto operations can implement
// this interface.
type CryptoOperator interface {

	// InjectKeyHolder injects a KeyHolder which will provide private keys
	// for the CryptoOperator's crypto computations.
	// Note: KeyHolders defined by the framework are not directly accessible
	// to clients -
	InjectKeyHolder(KeyHolder) error
}

// KeyHolder denotes an object that holds keypairs, indexed by the public key (in base 58)
type KeyHolder interface {
	// GetKey gets the keypair associated to the given pubkey
	GetKey(pub string) (*cryptoutil.KeyPair, error)

	// PutKey persists a keypair in the keystore
	PutKey(pub string, pair *cryptoutil.KeyPair) error
}
