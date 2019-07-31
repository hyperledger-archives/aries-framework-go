/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	errors "golang.org/x/xerrors"
)

const (
	//numAlgo is the algorithm for choosing a numeric basis Reference: https://openssi.github.io/peer-did-method-spec/index.html#method-specific-identifier
	numAlgo = "1"
	//encAlgo  is the algorithm for encoding
	encAlgo = "1"

	peerPrefix = "did:peer:"
)

//newDid creates the peer DID. For example : did:peer:11-479cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe
func newDid(doc *did.Doc) (string, error) {

	if doc.PublicKey == nil || doc.Authentication == nil {
		return "", errors.New("the genesis version must include public keys and authentication")
	}

	docBytes, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	hash, err := computeHash(docBytes)
	if err != nil {
		return "", err
	}
	numBasis := base64.URLEncoding.EncodeToString(hash)
	messageIdentifier := []string{peerPrefix, numAlgo, encAlgo, "-", numBasis}
	peerDID := strings.Join(messageIdentifier, "")

	return peerDID, nil
}

// computeHash will compute the hash for the supplied bytes
func computeHash(bytes []byte) ([]byte, error) {

	if len(bytes) == 0 {
		return nil, errors.New("empty bytes")
	}

	h := crypto.SHA256.New()
	hash := h.Sum(bytes)
	return hash, nil

}
