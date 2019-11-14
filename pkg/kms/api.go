/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

// TODO https://github.com/hyperledger/aries-framework-go/issues/752 Signer is not part of KMS and should be
//  moved elsewhere, merge KMS and KeyManager interface when Signer is removed.

// KMS Key Management Service interface
type KMS interface {
	KeyManager
	Signer
}

// KeyManager interface provides key management operations (create, find, get, derive, etc.)
type KeyManager interface {
	KeyConverter

	// CreateKeySet create a new public/private encryption and signature key pairs set.
	//
	// Returns:
	// string: key set ID
	// string: public signature key base58 encoded
	// error: error
	CreateKeySet() (string, string, error)

	// DeriveKEK will first fetch the corresponding private encryption key from the KMS for fromSigPubKey.
	// It will then derive a new KEK (Key encryption Key) using the above fetched private key with toEncPubKey. This
	// KEK can then be used as a shared key to encrypt content to be sent out to another agent.
	//
	// This function assumes both private encryption key matching fromPubKey and the public encryption key toPubKey
	// to be on curve25519.
	//
	// returns:
	// 		kek []byte the key encryption key used to decrypt a cek (a shared key)
	//		error in case of errors
	DeriveKEK(alg, apu, fromSigPubKey, toEncPubKey []byte) ([]byte, error)

	// FindVerKey will search the KMS to find stored keys that match any of candidateKeys and
	// 		return the index of the first match.
	//		candidateKeys are public verification (signature) keys
	// returns:
	// 		int index of candidateKeys that matches the first key found in the KMS
	//		error in case of errors (including ErrKeyNotFound)
	//
	//		in case of error, the index will be -1
	// Note: there is no need to return the found key as candidateKeys are signing keys.
	FindVerKey(candidateKeys [][]byte) (int, error)

	// FindVerKeyFromEncryptionKeys will search the KMS to find stored keys that match any of candidateKeys and
	// 		return the index of the first match.
	//		candidateKeys are public encryption keys, the corresponding signature keys will be fetched
	// returns:
	// 		int index of candidateKeys that matches the first key found in the KMS
	//		error in case of errors (including ErrKeyNotFound)
	//
	//		in case of error, the index will be -1
	// Note: the found verification key is returned here as candidateKeys are encryption keys.
	FindVerKeyFromEncryptionKeys(candidateKeys [][]byte) (int, string, error)

	// GetEncryptionKey will return the public encryption key corresponding to the public (signing) verKey argument
	GetEncryptionKey(verKey []byte) ([]byte, error)
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

// KeyConverter provides methods for converting signing to encryption keys
type KeyConverter interface {
	// ConvertToEncryptionKey creates and persists a Curve25519 keys created from the given raw Ed25519 signing pub key
	// returning the encryption pub key for this new key set.
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
