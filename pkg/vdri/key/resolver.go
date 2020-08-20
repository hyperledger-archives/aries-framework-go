/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"fmt"
	"regexp"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/pkg/vdri/fingerprint"
)

// Read expands did:key value to a DID document.
func (v *VDRI) Read(didKey string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
	parsed, err := did.Parse(didKey)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdri Read: failed to parse DID document: %w", err)
	}

	if !isValidMethodID(parsed.MethodSpecificID) {
		return nil, fmt.Errorf("vdri Read: invalid did:key method ID: %s", parsed.MethodSpecificID)
	}

	pubKeyBytes, err := fingerprint.PubKeyFromFingerprint(parsed.MethodSpecificID)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdri Read: failed to get key fingerPrint: %w", err)
	}

	// did:key can't add non converted encryption key as keyAgreement (unless it's added as an option just like creator,
	// it can be added and read here if needed. Below TODO is a reminder for this)
	// TODO find a way to get the Encryption key as in creator.go
	// for now keeping original ed25519 to X25519 key conversion as keyAgreement.
	keyAgr, err := keyAgreement(didKey, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("pub:key vdri Read: failed to fetch KeyAgreement: %w", err)
	}

	didKey = fmt.Sprintf("did:key:%s", parsed.MethodSpecificID)
	keyID := fmt.Sprintf("%s#%s", didKey, parsed.MethodSpecificID)
	publicKey := did.NewPublicKeyFromBytes(keyID, ed25519VerificationKey2018, didKey, pubKeyBytes)

	return createDoc(publicKey, keyAgr, didKey)
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}
