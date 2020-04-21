/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

const (
	schemaV1                   = "https://w3id.org/did/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
)

const (
	ed25519pub = 0xed // Ed25519 public key in multicodec table
	x25519pub  = 0xec // Curve25519 public key in multicodec table
)

// Build builds new DID document.
func (v *VDRI) Build(pubKey *vdriapi.PubKey, opts ...vdriapi.DocOpts) (*did.Doc, error) {
	if pubKey.Type != ed25519VerificationKey2018 {
		return nil, fmt.Errorf("not supported public key type: %s", pubKey.Type)
	}

	return createDoc(base58.Decode(pubKey.Value))
}

func createDoc(pubKeyValue []byte) (*did.Doc, error) {
	methodID := keyFingerprint(multicodec(ed25519pub), pubKeyValue)
	didKey := fmt.Sprintf("did:key:%s", methodID)
	keyID := fmt.Sprintf("%s#%s", didKey, methodID)

	pubKey := did.NewPublicKeyFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKeyValue)

	keyAgreement, err := keyAgreement(didKey, pubKeyValue)
	if err != nil {
		return nil, err
	}

	// Created/Updated time
	t := time.Now()

	return &did.Doc{
		Context:              []string{schemaV1},
		ID:                   didKey,
		PublicKey:            []did.PublicKey{*pubKey},
		Authentication:       []did.VerificationMethod{{PublicKey: *pubKey}},
		AssertionMethod:      []did.VerificationMethod{{PublicKey: *pubKey}},
		CapabilityDelegation: []did.VerificationMethod{{PublicKey: *pubKey}},
		CapabilityInvocation: []did.VerificationMethod{{PublicKey: *pubKey}},
		KeyAgreement:         []did.VerificationMethod{{PublicKey: *keyAgreement}},
		Created:              &t,
		Updated:              &t,
	}, nil
}

func keyFingerprint(multicodecValue, pubKeyValue []byte) string {
	mcLength := len(multicodecValue)
	buf := make([]uint8, mcLength+len(pubKeyValue))
	copy(buf, multicodecValue)
	copy(buf[mcLength:], pubKeyValue)

	return fmt.Sprintf("z%s", base58.Encode(buf))
}

func keyAgreement(didKey string, ed25519PubKey []byte) (*did.PublicKey, error) {
	curve25519PubKey, err := cryptoutil.PublicEd25519toCurve25519(ed25519PubKey)
	if err != nil {
		return nil, err
	}

	fingerprint := keyFingerprint(multicodec(x25519pub), curve25519PubKey)
	keyID := fmt.Sprintf("%s#%s", didKey, fingerprint)
	pubKey := did.NewPublicKeyFromBytes(keyID, x25519KeyAgreementKey2019, didKey, curve25519PubKey)

	return pubKey, nil
}

func multicodec(code uint64) []byte {
	buf := make([]byte, 2)
	binary.PutUvarint(buf, code)

	return buf
}
