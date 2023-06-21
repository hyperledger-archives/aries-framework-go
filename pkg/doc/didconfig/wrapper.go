/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/didconfig/verifier"
	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
	vdrapi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

const (
	// ContextV0 is did configuration context version 0.
	ContextV0 = verifier.ContextV0

	// ContextV1 is did configuration context version 1.
	ContextV1 = verifier.ContextV1
)

type didResolver interface {
	Resolve(did string, opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error)
}

// DIDConfigurationOpt is the DID Configuration decoding option.
type DIDConfigurationOpt = verifier.DIDConfigurationOpt

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) DIDConfigurationOpt {
	return verifier.WithJSONLDDocumentLoader(documentLoader)
}

// WithVDRegistry defines a vdr service.
func WithVDRegistry(didResolver didResolver) DIDConfigurationOpt {
	return verifier.WithVDRegistry(didResolver)
}

// VerifyDIDAndDomain will verify that there is valid domain linkage credential in did configuration
// for specified did and domain.
func VerifyDIDAndDomain(didConfig []byte, did, domain string, opts ...DIDConfigurationOpt) error {
	return verifier.VerifyDIDAndDomain(didConfig, did, domain, opts...)
}
