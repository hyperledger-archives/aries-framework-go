/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kidresolver

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/kmsdidkey"
	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// KIDResolver helps resolve the kid public key from a recipient 'kid' or a sender 'skid' during JWE decryption.
// The JWEDecrypter should be able to load the public key using a resolution scheme for a key reference found in the
// 'skid' JWE protected header/'kid' recipient header.
type KIDResolver interface {
	// Resolve a 'kid'/'skid' into a marshalled public key or error if key resolution fails.
	Resolve(string) (*cryptoapi.PublicKey, error)
}

// DIDKeyResolver resolves a 'kid'/'skid' containing a did:key value.
type DIDKeyResolver struct{}

// Resolve a 'kid'/'skid' protected header with a did:key value into a marshalled public key or error if key
// resolution fails.
func (k *DIDKeyResolver) Resolve(kid string) (*cryptoapi.PublicKey, error) {
	return kmsdidkey.EncryptionPubKeyFromDIDKey(kid)
}

// StoreResolver resolves a 'kid'/'skid' containing a kms ID value (JWK fingerprint) from a dedicated pre-loaded store.
// Note: this is not a kms keystore. This StoreResolver is useful in cases where a thirdparty store is needed. This is
// useful in unit tests and especially for test vectors using the ECDH-1PU Appendix B example to load the sender key
// so that recipients can resolve a predefined 'skid'. Aries Framework Go is using the DIDKeyResolver by default (for
// request without DID docs) and DIDDocResolver (for requests with existing DID connections).
type StoreResolver struct {
	// store where the kid key is potentially stored.
	Store storage.Store
}

// Resolve a 'kid'/'skid' by loading kid's PublicKey from a store or return an error if it fails.
func (s *StoreResolver) Resolve(kid string) (*cryptoapi.PublicKey, error) {
	var pubKey *cryptoapi.PublicKey

	mPubKey, err := s.Store.Get(kid)
	if err != nil {
		return nil, fmt.Errorf("storeResolver: failed to resolve kid from store: %w", err)
	}

	err = json.Unmarshal(mPubKey, &pubKey)
	if err != nil {
		return nil, fmt.Errorf("storeResolver: failed to unmarshal public key from DB: %w", err)
	}

	return pubKey, nil
}
