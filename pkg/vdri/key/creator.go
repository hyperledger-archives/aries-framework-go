/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/fingerprint"
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
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	var (
		publicKey, keyAgr *did.PublicKey
		err               error
		didKey            string
	)

	switch pubKey.Type {
	case ed25519VerificationKey2018:
		var keyID string

		didKey, keyID = fingerprint.CreateDIDKey(pubKey.Value)
		publicKey = did.NewPublicKeyFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKey.Value)

		keyAgr, err = keyAgreement(didKey, pubKey.Value)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("not supported public key type: %s", pubKey.Type)
	}

	// retrieve encryption key as keyAgreement from opts if available.
	didOpts := &vdriapi.CreateDIDOpts{}

	for _, o := range opts {
		o(didOpts)

		if didOpts.EncryptionKey != nil {
			keyAgr, err = vdriapi.RetrieveEncryptionKey(didKey, didOpts.EncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("invalid JWK encryption key: %w", err)
			}

			break
		}
	}

	return createDoc(publicKey, keyAgr, didKey)
}

func createDoc(pubKey, keyAgreement *did.PublicKey, didKey string) (*did.Doc, error) {
	// Created/Updated time
	t := time.Now()

	return &did.Doc{
		Context:   []string{schemaV1},
		ID:        didKey,
		PublicKey: []did.PublicKey{*pubKey},
		Authentication: []did.VerificationMethod{*did.NewReferencedVerificationMethod(pubKey,
			did.Authentication, false)},
		AssertionMethod: []did.VerificationMethod{*did.NewReferencedVerificationMethod(pubKey,
			did.AssertionMethod, false)},
		CapabilityDelegation: []did.VerificationMethod{*did.NewReferencedVerificationMethod(pubKey,
			did.CapabilityDelegation, false)},
		CapabilityInvocation: []did.VerificationMethod{*did.NewReferencedVerificationMethod(pubKey,
			did.CapabilityInvocation, false)},
		KeyAgreement: []did.VerificationMethod{*did.NewEmbeddedVerificationMethod(keyAgreement,
			did.KeyAgreement)},
		Created: &t,
		Updated: &t,
	}, nil
}

func keyAgreement(didKey string, ed25519PubKey []byte) (*did.PublicKey, error) {
	curve25519PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fp := fingerprint.KeyFingerprint(x25519pub, curve25519PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fp)
	pubKey := did.NewPublicKeyFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25519PubKey)

	return pubKey, nil
}
