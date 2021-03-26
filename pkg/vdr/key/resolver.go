/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"
	"regexp"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
)

// Read expands did:key value to a DID document.
func (v *VDR) Read(didKey string, _ ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
	parsed, err := did.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to parse DID document: %w", err)
	}

	if !isValidMethodID(parsed.MethodSpecificID) {
		return nil, fmt.Errorf("vdr Read: invalid did:key method ID: %s", parsed.MethodSpecificID)
	}

	pubKeyBytes, code, err := fingerprint.PubKeyFromFingerprint(parsed.MethodSpecificID)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to get key fingerPrint: %w", err)
	}

	didDoc, err := createDIDDocFromPubKey(parsed.MethodSpecificID, code, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("creating did document from public key failed: %w", err)
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

func createDIDDocFromPubKey(kid string, code uint64, pubKeyBytes []byte) (*did.Doc, error) {
	switch code {
	case fingerprint.ED25519PubKeyMultiCodec:
		return createEd25519DIDDoc(kid, pubKeyBytes)
	case fingerprint.BLS12381g2PubKeyMultiCodec, fingerprint.BLS12381g1g2PubKeyMultiCodec:
		return createBase58DIDDoc(kid, bls12381G2Key2020, pubKeyBytes)
	case fingerprint.P256PubKeyMultiCodec, fingerprint.P384PubKeyMultiCodec, fingerprint.P521PubKeyMultiCodec:
		return createBase58DIDDoc(kid, jsonWebKey2020, pubKeyBytes)
	}

	return nil, fmt.Errorf("unsupported key multicodec code [0x%x]", code)
}

func createBase58DIDDoc(kid, keyType string, pubKeyBytes []byte) (*did.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	keyID := fmt.Sprintf("%s#%s", didKey, kid)
	publicKey := did.NewVerificationMethodFromBytes(keyID, keyType, didKey, pubKeyBytes)

	didDoc := createDoc(publicKey, publicKey, didKey)

	return didDoc, nil
}

func createEd25519DIDDoc(kid string, pubKeyBytes []byte) (*did.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	// did:key can't add non converted encryption key as keyAgreement (unless it's added as an option just like creator,
	// it can be added and read here if needed. Below TODO is a reminder for this)
	// TODO find a way to get the Encryption key as in creator.go
	// for now keeping original ed25519 to X25519 key conversion as keyAgreement.
	keyAgr, err := keyAgreementFromEd25519(didKey, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to fetch KeyAgreement: %w", err)
	}

	keyID := fmt.Sprintf("%s#%s", didKey, kid)
	publicKey := did.NewVerificationMethodFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKeyBytes)

	didDoc := createDoc(publicKey, keyAgr, didKey)

	return didDoc, nil
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}
