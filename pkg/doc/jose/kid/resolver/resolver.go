/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	jsonWebKey2020            = "JsonWebKey2020"
	x25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019"
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

// DIDDocResolver helps resolves a KMS kid from 'kid'/'skid' with values set as didDoc[].KeyAgreement[].ID. The list of
// DIDDocs should contain both sender and recipients docs for proper resolutio during unpacking.
type DIDDocResolver struct {
	VDRRegistry vdrapi.Registry
}

// Resolve kid into a *cryptoapi.PublicKey with ID set as the KMS kid. Where kid matches the DID doc found in the vdr
// registry with first key entry matching doc.keyAgreement[].VerificationMethod.ID.
func (d *DIDDocResolver) Resolve(kid string) (*cryptoapi.PublicKey, error) {
	var (
		pubKey *cryptoapi.PublicKey
		err    error
	)

	if d.VDRRegistry == nil {
		return nil, errors.New("didDocResolver: missing vdr registry")
	}

	i := strings.Index(kid, "#")

	if i < 0 {
		return nil, fmt.Errorf("didDocResolver: kid is not KeyAgreement.ID: '%v'", kid)
	}

	didDoc, err := d.VDRRegistry.Resolve(kid[:i])
	if err != nil {
		return nil, fmt.Errorf("didDocResolver: for recipient DID doc resolution %w", err)
	}

	for _, ka := range didDoc.DIDDocument.KeyAgreement {
		k := &ka //nolint:gosec
		keyAgreementID := ka.VerificationMethod.ID

		if strings.HasPrefix(keyAgreementID, "#") {
			keyAgreementID = didDoc.DIDDocument.ID + keyAgreementID
		}

		pubKey, err = extractKey(kid, keyAgreementID, k)
		if err != nil {
			return nil, err
		}
	}

	return pubKey, nil
}

func extractKey(kid, keyAgreementID string, ka *did.Verification) (*cryptoapi.PublicKey, error) {
	var (
		pubKey *cryptoapi.PublicKey
		err    error
	)

	if strings.EqualFold(kid, keyAgreementID) {
		switch ka.VerificationMethod.Type {
		case x25519KeyAgreementKey2019:
			pubKey, err = buildX25519Key(ka)
			if err != nil {
				return nil, fmt.Errorf("didDocResolver: %w", err)
			}
		case jsonWebKey2020:
			pubKey, err = buildJWKKey(ka)
			if err != nil {
				return nil, fmt.Errorf("didDocResolver: %w", err)
			}
		default:
			return nil, fmt.Errorf("didDocResolver: can't build key from KayAgreement with type: '%v'",
				ka.VerificationMethod.Type)
		}
	}

	return pubKey, nil
}

func buildX25519Key(ka *did.Verification) (*cryptoapi.PublicKey, error) {
	pubKey := &cryptoapi.PublicKey{
		X:     ka.VerificationMethod.Value,
		Curve: "X25519",
		Type:  "OKP",
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return nil, fmt.Errorf("buildX25519: marshal key error: %w", err)
	}

	x25519KMSKID, err := jwkkid.CreateKID(mPubKey, kms.X25519ECDHKWType)
	if err != nil {
		return nil, fmt.Errorf("buildX25519: createKID error:%w", err)
	}

	pubKey.KID = x25519KMSKID

	return pubKey, nil
}

func buildJWKKey(ka *did.Verification) (*cryptoapi.PublicKey, error) {
	var (
		x  []byte
		y  []byte
		kt kms.KeyType
	)

	jwkKey := ka.VerificationMethod.JSONWebKey()
	switch k := jwkKey.Key.(type) {
	case *ecdsa.PublicKey:
		x = k.X.Bytes()
		y = k.Y.Bytes()
	case []byte:
		x = make([]byte, len(k))
		copy(x, k)
	default:
		return nil, fmt.Errorf("buildJWKKey: unsupported JWK format: (%T)", k)
	}

	pubKey := &cryptoapi.PublicKey{
		X:     x,
		Y:     y,
		Curve: jwkKey.Crv,
		Type:  jwkKey.Kty,
	}

	switch jwkKey.Crv {
	case elliptic.P256().Params().Name:
		kt = kms.NISTP256ECDHKWType
	case elliptic.P384().Params().Name:
		kt = kms.NISTP384ECDHKWType
	case elliptic.P521().Params().Name:
		kt = kms.NISTP521ECDHKWType
	case "X25519":
		kt = kms.X25519ECDHKWType
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return nil, fmt.Errorf("buildJWKKey: marshal key error: %w", err)
	}

	jwkKMSKID, err := jwkkid.CreateKID(mPubKey, kt)
	if err != nil {
		return nil, fmt.Errorf("buildJWKKey: createKID error:%w", err)
	}

	pubKey.KID = jwkKMSKID

	return pubKey, nil
}
