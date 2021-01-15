/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ed25519"
	"fmt"
	"time"

	gojose "github.com/square/go-jose/v3"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/create"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr/doc"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const (
	schemaV1                   = "https://w3id.org/did/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
)

const (
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	x25519pub = 0xec // Curve25519 public key in multicodec table
)

// Build builds new DID document.
func (v *VDR) Build(keyManager kms.KeyManager, opts ...create.Option) (*did.DocResolution, error) {
	createDIDOpts := &create.Opts{}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	var (
		publicKey, keyAgr *did.VerificationMethod
		err               error
		didKey            string
	)

	if len(createDIDOpts.PublicKeys) == 0 {
		_, pubKeyBytes, errCreate := keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if errCreate != nil {
			return nil, fmt.Errorf("failed to create and export public key: %w", errCreate)
		}

		createDIDOpts.PublicKeys = append(createDIDOpts.PublicKeys, doc.PublicKey{
			Type: ed25519VerificationKey2018,
			JWK:  gojose.JSONWebKey{Key: ed25519.PublicKey(pubKeyBytes)},
		})
	}

	switch createDIDOpts.PublicKeys[0].Type {
	case ed25519VerificationKey2018:
		var keyID string

		didKey, keyID = fingerprint.CreateDIDKey(createDIDOpts.PublicKeys[0].JWK.Key.(ed25519.PublicKey))
		publicKey = did.NewVerificationMethodFromBytes(keyID, ed25519VerificationKey2018, didKey,
			createDIDOpts.PublicKeys[0].JWK.Key.(ed25519.PublicKey))

		keyAgr, err = keyAgreement(didKey, createDIDOpts.PublicKeys[0].JWK.Key.(ed25519.PublicKey))
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("not supported public key type: %s", createDIDOpts.PublicKeys[0].Type)
	}

	// retrieve encryption key as keyAgreement from opts if available.
	if createDIDOpts.EncryptionKey != nil {
		keyAgr, err = retrieveEncryptionKey(didKey, createDIDOpts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("invalid JWK encryption key: %w", err)
		}
	}

	didDoc := createDoc(publicKey, keyAgr, didKey)

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

func createDoc(pubKey, keyAgreement *did.VerificationMethod, didKey string) *did.Doc {
	// Created/Updated time
	t := time.Now()

	return &did.Doc{
		Context:            []string{schemaV1},
		ID:                 didKey,
		VerificationMethod: []did.VerificationMethod{*pubKey},
		Authentication: []did.Verification{*did.NewReferencedVerification(pubKey,
			did.Authentication)},
		AssertionMethod: []did.Verification{*did.NewReferencedVerification(pubKey,
			did.AssertionMethod)},
		CapabilityDelegation: []did.Verification{*did.NewReferencedVerification(pubKey,
			did.CapabilityDelegation)},
		CapabilityInvocation: []did.Verification{*did.NewReferencedVerification(pubKey,
			did.CapabilityInvocation)},
		KeyAgreement: []did.Verification{*did.NewEmbeddedVerification(keyAgreement,
			did.KeyAgreement)},
		Created: &t,
		Updated: &t,
	}
}

func keyAgreement(didKey string, ed25519PubKey []byte) (*did.VerificationMethod, error) {
	curve25519PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fp := fingerprint.KeyFingerprint(x25519pub, curve25519PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fp)
	pubKey := did.NewVerificationMethodFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25519PubKey)

	return pubKey, nil
}

// retrieveEncryptionKey retrieves an encryption VerificationMethod in JWK format from key.
func retrieveEncryptionKey(didKey string, key *doc.PublicKey) (*did.VerificationMethod, error) {
	keyID := fmt.Sprintf("%s#%s", didKey, key.ID)

	jwk, err := jwkFromJSONWebKey(&key.JWK)
	if err != nil {
		return nil, err
	}

	publicKey, err := did.NewVerificationMethodFromJWK(keyID, key.Type, didKey, jwk)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func jwkFromJSONWebKey(jwk *gojose.JSONWebKey) (*jose.JWK, error) {
	key := &jose.JWK{JSONWebKey: *jwk}

	// marshal/unmarshal to get all JWK's fields other than Key filled.
	keyBytes, err := key.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	err = key.UnmarshalJSON(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("create JWK: %w", err)
	}

	return key, nil
}
