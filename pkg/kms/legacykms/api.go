/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package legacykms

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
	// string: enc public key of the encryption keypair
	// string: sig public key of the signature keypair
	// error: error
	CreateKeySet() (string, string, error)

	// DeriveKEK will derive an ephemeral symmetric key (kek) using a private from key fetched from
	// from the LegacyKMS corresponding to fromPubKey and derived with toPubKey.
	//
	// This function assumes both fromPubKey and toPubKey to be on curve25519.
	//
	// returns:
	// 		kek []byte the key encryption key used to decrypt a cek (a shared key)
	//		error in case of errors
	DeriveKEK(alg, apu, fromPubKey, toPubKey []byte) ([]byte, error)

	// FindVerKey will search the LegacyKMS to find stored keys that match any of candidateKeys and
	// 		return the index of the first match
	// returns:
	// 		int index of candidateKeys that matches the first key found in the LegacyKMS
	//		error in case of errors (including ErrKeyNotFound)
	//
	//		in case of error, the index will be -1
	FindVerKey(candidateKeys []string) (int, error)

	// GetEncryptionKey will return the public encryption key corresponding to the public verKey argument
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
