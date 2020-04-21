/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/btcsuite/btcutil/base58"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
)

// Read expands did:key value to a DID document.
func (v *VDRI) Read(didKey string, opts ...vdriapi.ResolveOpts) (*did.Doc, error) {
	parsed, err := did.Parse(didKey)
	if err != nil {
		return nil, err
	}

	if !isValidMethodID(parsed.MethodSpecificID) {
		return nil, fmt.Errorf("invalid did:key method ID: %s", parsed.MethodSpecificID)
	}

	pubKey, err := pubKeyFromFingerprint(parsed.MethodSpecificID)
	if err != nil {
		return nil, err
	}

	return createDoc(pubKey)
}

func isValidMethodID(id string) bool {
	r := regexp.MustCompile(`(z)([1-9a-km-zA-HJ-NP-Z]{46})`)
	return r.MatchString(id)
}

func pubKeyFromFingerprint(fingerprint string) ([]byte, error) {
	// did:key:MULTIBASE(base58-btc, MULTICODEC(public-key-type, raw-public-key-bytes))
	// https://w3c-ccg.github.io/did-method-key/#format
	mc := base58.Decode(fingerprint[1:]) // skip leading "z"
	if !bytes.Equal(multicodec(ed25519pub), mc[:2]) {
		return nil, fmt.Errorf("not supported public key (multicodec code: %#x)", mc[0])
	}

	return mc[2:], nil
}
