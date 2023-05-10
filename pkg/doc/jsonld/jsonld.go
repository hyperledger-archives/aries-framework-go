/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/models/ld/validator"
)

// ValidateOpts sets jsonld validation options.
type ValidateOpts = validator.ValidateOpts

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(jsonldDocumentLoader ld.DocumentLoader) validator.ValidateOpts {
	return validator.WithDocumentLoader(jsonldDocumentLoader)
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(externalContext []string) validator.ValidateOpts {
	return validator.WithExternalContext(externalContext)
}

// WithStrictValidation sets if strict validation should be used.
func WithStrictValidation(checkStructure bool) ValidateOpts {
	return validator.WithStrictValidation(checkStructure)
}

// WithStrictContextURIPosition sets strict validation of URI position within context property.
// The index of uri in underlying slice represents the position of given uri in @context array.
// Can be used for verifiable credential base context validation.
func WithStrictContextURIPosition(uri string) ValidateOpts {
	return validator.WithStrictContextURIPosition(uri)
}

// ValidateJSONLD validates jsonld structure.
func ValidateJSONLD(doc string, options ...ValidateOpts) error {
	return validator.ValidateJSONLD(doc, options...)
}
