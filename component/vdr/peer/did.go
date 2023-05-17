/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/jinzhu/copier"
	"github.com/multiformats/go-multibase"
	"github.com/multiformats/go-multihash"

	"github.com/hyperledger/aries-framework-go/component/models/did"
)

const (
	// Reference: https://identity.foundation/peer-did-method-spec/#method-specific-identifier
	// numAlgo is the algorithm for choosing a numeric basis.
	numAlgo = "1"
	// The transform is base58, represented by the multibase prefix z as per spec.
	transform = multibase.Base58BTC

	peerPrefix = "did:peer:"

	// DIDMethod is the peer did method name: https://identity.foundation/peer-did-method-spec/#method-name.
	DIDMethod = "peer"
)

var didRegex = regexp.MustCompile(`did:peer:(1)(z)([1-9a-km-zA-HJ-NP-Z]{46})`)

// NewDoc returns the resolved variant of the genesis version of the peer DID document.
func NewDoc(publicKey []did.VerificationMethod, opts ...did.DocOption) (*did.Doc, error) {
	if len(publicKey) == 0 {
		return nil, fmt.Errorf("the did:peer genesis version must include public keys and authentication")
	}

	// build DID Doc
	doc := did.BuildDoc(append([]did.DocOption{did.WithVerificationMethod(publicKey)}, opts...)...)

	// Create a did doc based on the mandatory value: publicKeys & authentication
	if len(doc.Authentication) == 0 || len(doc.VerificationMethod) == 0 {
		return nil, fmt.Errorf("the did:peer genesis version must include public keys and authentication")
	}

	id, err := computeDidMethod1(doc)
	if err != nil {
		return nil, err
	}

	doc.ID = id

	return doc, nil
}

// computeDidMethod1 creates the peer DID.
// For example: did:peer:1zQmZMygzYqNwU6Uhmewx5Xepf2VLp5S4HLSwwgf2aiKZuwa.
// Reference: https://identity.foundation/peer-did-method-spec/#generation-method
func computeDidMethod1(doc *did.Doc) (string, error) {
	if doc.VerificationMethod == nil || doc.Authentication == nil {
		return "", errors.New("the genesis version must include public keys and authentication")
	}

	encNumBasis, err := calculateEncNumBasis(doc)
	if err != nil {
		return "", err
	}

	messageIdentifier := []string{peerPrefix, encNumBasis}

	return strings.Join(messageIdentifier, ""), nil
}

// validateDID checks the format of the doc's DID and checks that the DID's 'namestring' matches against its enc numeric
// basis as per the Namestring Generation Method.
// Reference: https://identity.foundation/peer-did-method-spec/#method-specific-identifier
//
// Note: this check should be done only on the resolved variant of the genesis version of Peer DID documents.
func validateDID(doc *did.Doc) error {
	peerDid := doc.ID

	matched := didRegex.MatchString(peerDid)
	if !matched {
		return fmt.Errorf("validate did : %w", errors.New("did doesnt follow matching regex"))
	}

	// extracting numbasis from the validated did
	splitDid := strings.FieldsFunc(peerDid, func(r rune) bool { return r == ':' })
	encnumbasis := splitDid[2]

	genesisDoc := &did.Doc{}

	err := copier.Copy(genesisDoc, doc)
	if err != nil {
		return fmt.Errorf("failed to copy did doc for methodID calculation: %w", err)
	}

	// calculate the encnumbasis of the genesis version of the peer DID doc
	// TODO the ID is not being removed from other places in the did doc
	genesisDoc.ID = ""

	// calculate the encnumbasis of the genesis version of the peer DID doc
	numBas, err := calculateEncNumBasis(genesisDoc)
	if err != nil {
		return fmt.Errorf("validate did : %w", err)
	}

	if !(numBas == encnumbasis) {
		return fmt.Errorf("validate did : %w", errors.New("multiHash of the doc doesnt match the computed multiHash"))
	}

	return nil
}

// calculateEncNumBasis is multicodec numeric basis.
// Reference : https://identity.foundation/peer-did-method-spec/#dfn-multicodec-descriptor
func calculateEncNumBasis(doc *did.Doc) (string, error) {
	docBytes, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}

	hash, err := multihash.Sum(docBytes, multihash.SHA2_256, -1)
	if err != nil {
		return "", err
	}

	messageIdentifier := []string{numAlgo, string(transform), hash.B58String()}

	return strings.Join(messageIdentifier, ""), nil
}
