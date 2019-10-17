/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

// Wallet interface
type Wallet interface {
	Crypto
	Signer
	DIDCreator
}

// Crypto interface
type Crypto interface {

	// CreateEncryptionKey create a new public/private encryption keypair.
	//
	// Returns:
	//
	// string: verKey
	//
	// error: error
	CreateEncryptionKey() (string, error)

	// CreateSigningKey create a new public/private signing keypair.
	//
	// Returns:
	//
	// string: verKey
	//
	// error: error
	CreateSigningKey() (string, error)

	// DeriveKEK will derive an ephemeral symmetric key (kek) using a private from key fetched from
	// from the wallet corresponding to fromPubKey and derived with toPubKey.
	//
	// This function assumes both fromPubKey and toPubKey to be on curve25519.
	//
	// returns:
	// 		kek []byte the key encryption key used to decrypt a cek (a shared key)
	//		error in case of errors
	DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error)

	// FindVerKey will search the wallet to find stored keys that match any of candidateKeys and
	// 		return the index of the first match
	// returns:
	// 		int index of candidateKeys that matches the first key found in the wallet
	//		error in case of errors (including ErrKeyNotFound)
	//
	//		in case of error, the index will be -1
	FindVerKey(candidateKeys []string) (int, error)
}

// Signer interface provides signing capabilities
type Signer interface {

	// SignMessage sign a message using the private key associated with a given verification key.
	//
	// Args:
	//
	// message: The message to sign
	//
	// fromVerKey: Sign using the private key related to this verification key
	//
	// Returns:
	//
	// []byte: The signature
	//
	// error: error
	SignMessage(message []byte, fromVerKey string) ([]byte, error)
}

// DIDCreator provides features to create and query DID document
type DIDCreator interface {
	// Creates new DID document.
	//
	// Args:
	//
	// method: DID method
	//
	// opts: options to create DID
	//
	// Returns:
	//
	// did: DID document
	//
	// error: error
	CreateDID(method string, opts ...DocOpts) (*did.Doc, error)

	// Gets already created DID document by ID.
	//
	// Args:
	//
	// id: DID identifier
	//
	// Returns:
	//
	// did: DID document
	//
	// error: when document is not found or for any other error conditions
	GetDID(id string) (*did.Doc, error)
}

// KeyConverter provides methods for converting signing to encryption keys
type KeyConverter interface {
	// ConvertToEncryptionKey creates and persists a Curve25519 keypair created from the given SigningPubKey's
	// Ed25519 keypair, returning the EncryptionPubKey for this new keypair.
	ConvertToEncryptionKey(key []byte) ([]byte, error)
}

// createDIDOpts holds the options for creating DID
type createDIDOpts struct {
	serviceType string
}

// DocOpts is a create DID option
type DocOpts func(opts *createDIDOpts)

// WithServiceType service type of DID document to be created
func WithServiceType(serviceType string) DocOpts {
	return func(opts *createDIDOpts) {
		opts.serviceType = serviceType
	}
}
