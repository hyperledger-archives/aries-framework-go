/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"
	"time"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/util/cryptoutil"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

const (
	schemaResV1                = "https://w3id.org/did-resolution/v1"
	schemaDIDV1                = "https://w3id.org/did/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	bls12381G2Key2020          = "Bls12381G2Key2020"
	jsonWebKey2020             = "JsonWebKey2020"
)

// Create new DID document for didDoc.
// Either didDoc must contain non-empty VerificationMethod[] or opts must contain KeyType value of kms.KeyType to create
// a new key and a corresponding *VerificationMethod entry.
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	createDIDOpts := &vdrspi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(createDIDOpts)
	}

	var (
		publicKey, keyAgr *did.VerificationMethod
		err               error
		didKey            string
		keyID             string
		keyCode           uint64
	)

	if len(didDoc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("verification method is empty")
	}

	switch didDoc.VerificationMethod[0].Type {
	case jsonWebKey2020:
		didKey, keyID, err = fingerprint.CreateDIDKeyByJwk(didDoc.VerificationMethod[0].JSONWebKey())
		if err != nil {
			return nil, err
		}
	default:
		keyCode, err = getKeyCode(&didDoc.VerificationMethod[0])
		if err != nil {
			return nil, err
		}

		didKey, keyID = fingerprint.CreateDIDKeyByCode(keyCode, didDoc.VerificationMethod[0].Value)
	}

	publicKey = did.NewVerificationMethodFromBytes(keyID, didDoc.VerificationMethod[0].Type, didKey,
		didDoc.VerificationMethod[0].Value)

	if didDoc.VerificationMethod[0].Type == ed25519VerificationKey2018 {
		keyAgr, err = keyAgreementFromEd25519(didKey, didDoc.VerificationMethod[0].Value)
		if err != nil {
			return nil, err
		}
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

	return &did.DocResolution{Context: []string{schemaResV1}, DIDDocument: createDoc(publicKey, keyAgr, didKey)}, nil
}

func getKeyCode(verificationMethod *did.VerificationMethod) (uint64, error) {
	var keyCode uint64

	switch verificationMethod.Type {
	case ed25519VerificationKey2018:
		keyCode = fingerprint.ED25519PubKeyMultiCodec
	case bls12381G2Key2020:
		keyCode = fingerprint.BLS12381g2PubKeyMultiCodec
	default:
		return 0, fmt.Errorf("not supported public key type: %s", verificationMethod.Type)
	}

	return keyCode, nil
}

func createDoc(pubKey, keyAgreement *did.VerificationMethod, didKey string) *did.Doc {
	// Created/Updated time
	t := time.Now()

	kaVerification := make([]did.Verification, 0)

	if keyAgreement != nil {
		kaVerification = []did.Verification{*did.NewEmbeddedVerification(keyAgreement, did.KeyAgreement)}
	}

	return &did.Doc{
		Context:              []string{schemaDIDV1},
		ID:                   didKey,
		VerificationMethod:   []did.VerificationMethod{*pubKey},
		Authentication:       []did.Verification{*did.NewReferencedVerification(pubKey, did.Authentication)},
		AssertionMethod:      []did.Verification{*did.NewReferencedVerification(pubKey, did.AssertionMethod)},
		CapabilityDelegation: []did.Verification{*did.NewReferencedVerification(pubKey, did.CapabilityDelegation)},
		CapabilityInvocation: []did.Verification{*did.NewReferencedVerification(pubKey, did.CapabilityInvocation)},
		KeyAgreement:         kaVerification,
		Created:              &t,
		Updated:              &t,
	}
}

func keyAgreementFromEd25519(didKey string, ed25519PubKey []byte) (*did.VerificationMethod, error) {
	curve25519PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fp := fingerprint.KeyFingerprint(fingerprint.X25519PubKeyMultiCodec, curve25519PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fp)
	pubKey := did.NewVerificationMethodFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25519PubKey)

	return pubKey, nil
}
