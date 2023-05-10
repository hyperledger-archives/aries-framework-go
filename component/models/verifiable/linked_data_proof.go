/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	ldprocessor "github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/ld/proof"
	"github.com/hyperledger/aries-framework-go/component/models/signature/signer"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

const (
	resolveIDParts = 2
)

type keyResolverAdapter struct {
	pubKeyFetcher PublicKeyFetcher
}

func (k *keyResolverAdapter) Resolve(id string) (*verifier.PublicKey, error) {
	// id will contain didID#keyID
	idSplit := strings.Split(id, "#")
	if len(idSplit) != resolveIDParts {
		return nil, fmt.Errorf("wrong id %s to resolve", idSplit)
	}
	// idSplit[0] is didID
	// idSplit[1] is keyID
	pubKey, err := k.pubKeyFetcher(idSplit[0], fmt.Sprintf("#%s", idSplit[1]))
	if err != nil {
		return nil, err
	}

	return pubKey, nil
}

// SignatureRepresentation is a signature value holder type (e.g. "proofValue" or "jws").
type SignatureRepresentation int

const (
	// SignatureProofValue uses "proofValue" field in a Proof to put/read a digital signature.
	SignatureProofValue SignatureRepresentation = iota

	// SignatureJWS uses "jws" field in a Proof as an element for representation of detached JSON Web Signatures.
	SignatureJWS
)

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext struct {
	SignatureType           string                  // required
	Suite                   signer.SignatureSuite   // required
	SignatureRepresentation SignatureRepresentation // required
	Created                 *time.Time              // optional
	VerificationMethod      string                  // optional
	Challenge               string                  // optional
	Domain                  string                  // optional
	Purpose                 string                  // optional
	// CapabilityChain must be an array. Each element is either a string or an object.
	CapabilityChain []interface{}
}

func checkLinkedDataProof(jsonldBytes map[string]interface{}, suites []verifier.SignatureSuite,
	pubKeyFetcher PublicKeyFetcher, jsonldOpts *jsonldCredentialOpts) error {
	documentVerifier, err := verifier.New(&keyResolverAdapter{pubKeyFetcher}, suites...)
	if err != nil {
		return fmt.Errorf("create new signature verifier: %w", err)
	}

	processorOpts := mapJSONLDProcessorOpts(jsonldOpts)

	err = documentVerifier.VerifyObject(jsonldBytes, processorOpts...)
	if err != nil {
		return fmt.Errorf("check linked data proof: %w", err)
	}

	return nil
}

func mapJSONLDProcessorOpts(jsonldOpts *jsonldCredentialOpts) []ldprocessor.Opts {
	var processorOpts []ldprocessor.Opts

	if jsonldOpts.jsonldDocumentLoader != nil {
		processorOpts = append(processorOpts, ldprocessor.WithDocumentLoader(jsonldOpts.jsonldDocumentLoader))
	}

	if jsonldOpts.jsonldOnlyValidRDF {
		processorOpts = append(processorOpts, ldprocessor.WithRemoveAllInvalidRDF())
	} else {
		processorOpts = append(processorOpts, ldprocessor.WithValidateRDF())
	}

	return processorOpts
}

type rawProof struct {
	Proof json.RawMessage `json:"proof,omitempty"`
}

// addLinkedDataProof adds a new proof to the JSON-LD document (VC or VP). It returns a slice
// of the proofs which were already present appended with a newly created proof.
func addLinkedDataProof(context *LinkedDataProofContext, jsonldBytes []byte,
	opts ...ldprocessor.Opts) ([]Proof, error) {
	documentSigner := signer.New(context.Suite)

	vcWithNewProofBytes, err := documentSigner.Sign(mapContext(context), jsonldBytes, opts...)
	if err != nil {
		return nil, fmt.Errorf("add linked data proof: %w", err)
	}

	// Get a proof from json-ld document.
	var rProof rawProof

	err = json.Unmarshal(vcWithNewProofBytes, &rProof)
	if err != nil {
		return nil, err
	}

	proofs, err := parseProof(rProof.Proof)
	if err != nil {
		return nil, err
	}

	return proofs, nil
}

func mapContext(context *LinkedDataProofContext) *signer.Context {
	return &signer.Context{
		SignatureType:           context.SignatureType,
		SignatureRepresentation: proof.SignatureRepresentation(context.SignatureRepresentation),
		Created:                 context.Created,
		VerificationMethod:      context.VerificationMethod,
		Challenge:               context.Challenge,
		Domain:                  context.Domain,
		Purpose:                 context.Purpose,
		CapabilityChain:         context.CapabilityChain,
	}
}
