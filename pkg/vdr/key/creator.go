/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

const (
	schemaV1                   = "https://w3id.org/did/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	bls12381G2Key2020          = "Bls12381G2Key2020"
)

const (
	// source: https://github.com/multiformats/multicodec/blob/master/table.csv.
	x25519pub     = 0xec // Curve25519 public key in multicodec table
	ed25519pub    = 0xed // Ed25519 public key in multicodec table
	bls12381g2pub = 0xeb // BLS12-381 G2 public key in multicodec table
)

// Create new DID document.
func (v *VDR) Create(keyManager kms.KeyManager, didDoc *did.Doc,
	opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	createDIDOpts := &vdrapi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	var (
		publicKey, keyAgr *did.VerificationMethod
		err               error
		didKey            string
	)

	if len(didDoc.VerificationMethod) == 0 {
		_, pubKeyBytes, errCreate := keyManager.CreateAndExportPubKeyBytes(kms.ED25519Type)
		if errCreate != nil {
			return nil, fmt.Errorf("failed to create and export public key: %w", errCreate)
		}

		didDoc.VerificationMethod = append(didDoc.VerificationMethod, did.VerificationMethod{
			Type:  ed25519VerificationKey2018,
			Value: pubKeyBytes,
		})
	}

	switch didDoc.VerificationMethod[0].Type {
	case ed25519VerificationKey2018:
		var keyID string

		didKey, keyID = fingerprint.CreateDIDKey(didDoc.VerificationMethod[0].Value)
		publicKey = did.NewVerificationMethodFromBytes(keyID, ed25519VerificationKey2018, didKey,
			didDoc.VerificationMethod[0].Value)

		keyAgr, err = keyAgreementFromEd25519(didKey, didDoc.VerificationMethod[0].Value)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("not supported public key type: %s", didDoc.VerificationMethod[0].Type)
	}

	// retrieve encryption key as keyAgreement from opts if available.
	k := createDIDOpts.Values[EncryptionKey]
	if k != nil {
		var ok bool
		keyAgr, ok = k.(*did.VerificationMethod)

		if !ok {
			return nil, fmt.Errorf("encryptionKey not VerificationMethod")
		}
	}

	return &did.DocResolution{DIDDocument: createDoc(publicKey, keyAgr, didKey)}, nil
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

func keyAgreementFromEd25519(didKey string, ed25519PubKey []byte) (*did.VerificationMethod, error) {
	curve25519PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fp := fingerprint.KeyFingerprint(x25519pub, curve25519PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fp)
	pubKey := did.NewVerificationMethodFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25519PubKey)

	return pubKey, nil
}
