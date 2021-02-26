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
func (v *VDR) Read(didKey string, opts ...vdrapi.ResolveOption) (*did.DocResolution, error) {
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

	// TODO: support additional codes for did:key
	switch code {
	case ed25519pub:
		break
	default:
		return nil, fmt.Errorf("unsupported key multicodec code [0x%x]", code)
	}

	// did:key can't add non converted encryption key as keyAgreement (unless it's added as an option just like creator,
	// it can be added and read here if needed. Below TODO is a reminder for this)
	// TODO find a way to get the Encryption key as in creator.go
	// for now keeping original ed25519 to X25519 key conversion as keyAgreement.
	keyAgr, err := keyAgreement(didKey, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdr Read: failed to fetch KeyAgreement: %w", err)
	}

	didKey = fmt.Sprintf("did:key:%s", parsed.MethodSpecificID)
	keyID := fmt.Sprintf("%s#%s", didKey, parsed.MethodSpecificID)
	publicKey := did.NewVerificationMethodFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKeyBytes)

	didDoc := createDoc(publicKey, keyAgr, didKey)

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}
