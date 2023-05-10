/*
Copyright Gen Digital Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package diddocresolver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/vdr"
)

const (
	jsonWebKey2020            = "JsonWebKey2020"
	x25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019"
)

type vdrResolver interface {
	Resolve(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

// DIDDocResolver helps resolves a KMS kid from 'kid'/'skid' with values set as didDoc[].KeyAgreement[].ID. The list of
// DIDDocs should contain both sender and recipients docs for proper resolution during unpacking.
type DIDDocResolver struct {
	VDRRegistry vdrResolver
}

// Resolve kid into a *cryptoapi.PublicKey with ID set as the KMS kid. Where kid matches the DID doc found in the vdr
// registry with first key entry matching doc.keyAgreement[].VerificationMethod.ID.
func (d *DIDDocResolver) Resolve(kid string) (*crypto.PublicKey, error) {
	var (
		pubKey *crypto.PublicKey
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

func extractKey(kid, keyAgreementID string, ka *did.Verification) (*crypto.PublicKey, error) {
	var (
		pubKey *crypto.PublicKey
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

func buildX25519Key(ka *did.Verification) (*crypto.PublicKey, error) {
	pubKey := &crypto.PublicKey{
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

func buildJWKKey(ka *did.Verification) (*crypto.PublicKey, error) {
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

	pubKey := &crypto.PublicKey{
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
