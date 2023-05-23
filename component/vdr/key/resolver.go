/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"regexp"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// Read expands did:key value to a DID document.
func (v *VDR) Read(didKey string, _ ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	parsed, err := did.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to parse DID document: %w", err)
	}

	if parsed.Method != "key" {
		return nil, fmt.Errorf("vdr Read: invalid did:key method: %s", parsed.Method)
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

	return &did.DocResolution{Context: []string{schemaResV1}, DIDDocument: didDoc}, nil
}

func createDIDDocFromPubKey(kid string, code uint64, pubKeyBytes []byte) (*did.Doc, error) {
	switch code {
	case fingerprint.ED25519PubKeyMultiCodec:
		return createEd25519DIDDoc(kid, pubKeyBytes)
	case fingerprint.BLS12381g2PubKeyMultiCodec, fingerprint.BLS12381g1g2PubKeyMultiCodec:
		return createBase58DIDDoc(kid, bls12381G2Key2020, pubKeyBytes)
	case fingerprint.P256PubKeyMultiCodec, fingerprint.P384PubKeyMultiCodec, fingerprint.P521PubKeyMultiCodec:
		return createJSONWebKey2020DIDDoc(kid, code, pubKeyBytes)
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

func createJSONWebKey2020DIDDoc(kid string, code uint64, pubKeyBytes []byte) (*did.Doc, error) {
	didKey := fmt.Sprintf("did:key:%s", kid)

	keyID := fmt.Sprintf("%s#%s", didKey, kid)

	var curve elliptic.Curve

	switch code {
	case fingerprint.P256PubKeyMultiCodec:
		curve = elliptic.P256()
	case fingerprint.P384PubKeyMultiCodec:
		curve = elliptic.P384()
	case fingerprint.P521PubKeyMultiCodec:
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported key multicodec code for JsonWebKey2020 [0x%x]", code)
	}

	x, y := elliptic.UnmarshalCompressed(curve, pubKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("error unmarshalling key bytes")
	}

	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	j, err := jwksupport.JWKFromKey(&publicKey)
	if err != nil {
		return nil, fmt.Errorf("error creating JWK %w", err)
	}

	vm, err := did.NewVerificationMethodFromJWK(keyID, jsonWebKey2020, didKey, j)
	if err != nil {
		return nil, fmt.Errorf("error creating verification method %w", err)
	}

	didDoc := createDoc(vm, vm, didKey)

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
