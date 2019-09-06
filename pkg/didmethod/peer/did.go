/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"crypto"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

const (
	// numAlgo is the algorithm for choosing a numeric basis.
	// Reference: https://openssi.github.io/peer-did-method-spec/index.html#method-specific-identifier
	numAlgo = "1"
	// encAlgo  is the algorithm for encoding
	encAlgo = "1"

	peerPrefix = "did:peer:"
)

// NewDoc returns the resolved variant of the genesis version of the peer DID document
func NewDoc(publicKey []did.PublicKey, authorization []did.VerificationMethod) (*did.Doc, error) {

	// Create a did doc based on the mandatory value: publicKeys & authorization
	doc := &did.Doc{PublicKey: publicKey, Authentication: authorization}

	id, err := computeDid(doc)
	if err != nil {
		return nil, err
	}
	doc.ID = id
	return doc, nil

}

// computeDid creates the peer DID.
// For example: did:peer:11-479cbc07c3f991725836a3aa2a581ca2029198aa420b9d99bc0e131d9f3e2cbe
func computeDid(doc *did.Doc) (string, error) {

	if doc.PublicKey == nil || doc.Authentication == nil {
		return "", errors.New("the genesis version must include public keys and authentication")
	}
	numBasis, err := numBasis(doc)
	if err != nil {
		return "", err
	}
	messageIdentifier := []string{peerPrefix, numAlgo, encAlgo, "-", numBasis}
	peerDID := strings.Join(messageIdentifier, "")

	return peerDID, nil
}

// validateDID checks the format of the doc's DID and checks that the DID's 'namestring' matches against its numeric
// basis as per the Namestring Generation Method.
// Reference: https://openssi.github.io/peer-did-method-spec/index.html#namestring-generation-method
//
// Note: this check should be done only on the resolved variant of the genesis version of Peer DID documents.
func validateDID(doc *did.Doc) error {

	peerDid := doc.ID

	matched, err := regexp.MatchString(`did:peer:11-([a-fA-F0-9]){64}`, peerDid)
	if err != nil {
		return fmt.Errorf("regex match string failed %w", err)
	}
	if !matched {
		return fmt.Errorf("did doesnt follow matching regex")
	}

	// extracting numbasis from the validated did
	splitDid := strings.FieldsFunc(peerDid, func(r rune) bool { return r == '-' })
	extractedNumBasis := splitDid[1]

	// genesis version(no did) of the peer DID doc
	genesisDoc := &did.Doc{
		Context:        doc.Context,
		ID:             "",
		PublicKey:      doc.PublicKey,
		Service:        doc.Service,
		Authentication: doc.Authentication,
		Created:        doc.Created,
		Updated:        doc.Updated,
		Proof:          doc.Proof,
	}

	// calculate the numbasis of the genesis version of the peer DID doc
	numBas, err := numBasis(genesisDoc)
	if err != nil {
		return err
	}

	if !(numBas == extractedNumBasis) {
		return errors.New("hash of the doc doesnt match the computed hash")
	}
	return nil
}

// numBasis is numeric basis. The spec requires a 256-bit (encoded using 64 hexadecimal digits) numBasis generated
// from a hash of the initial content of a DID doc i.e genesis doc.
//
//  Reference : https://dhh1128.github.io/peer-did-method-spec/#matching-regex
func numBasis(doc *did.Doc) (string, error) {
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	hash, err := computeHash(docBytes)
	if err != nil {
		return "", err
	}
	numBasis := hex.EncodeToString(hash)

	return numBasis, nil
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
