/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
)

// ErrInvalidRDFFound is returned when normalized view contains invalid RDF.
var ErrInvalidRDFFound = processor.ErrInvalidRDFFound

// ProcessorOpts are the options for JSON LD operations on docs (like canonicalization or compacting).
type ProcessorOpts = processor.Opts

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalize document.
func WithRemoveAllInvalidRDF() ProcessorOpts {
	return processor.WithRemoveAllInvalidRDF()
}

// WithFrameBlankNodes option for transforming blank node identifiers into nodes.
// For example, _:c14n0 is transformed into <urn:bnid:_:c14n0>.
func WithFrameBlankNodes() ProcessorOpts {
	return processor.WithFrameBlankNodes()
}

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(loader ld.DocumentLoader) ProcessorOpts {
	return processor.WithDocumentLoader(loader)
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(context ...string) ProcessorOpts {
	return processor.WithExternalContext(context...)
}

// WithValidateRDF option validates result view and fails if any invalid RDF dataset found.
// This option will take precedence when used in conjunction with 'WithRemoveAllInvalidRDF' option.
func WithValidateRDF() ProcessorOpts {
	return processor.WithValidateRDF()
}

// Processor is JSON-LD processor for aries.
// processing mode JSON-LD 1.0 {RFC: https://www.w3.org/TR/2014/REC-json-ld-20140116}
type Processor = processor.Processor

// NewProcessor returns new JSON-LD processor for aries.
func NewProcessor(algorithm string) *Processor {
	return processor.NewProcessor(algorithm)
}

// Default returns new JSON-LD processor with default RDF dataset algorithm.
func Default() *Processor {
	return processor.Default()
}

// AppendExternalContexts appends external context(s) to the JSON-LD context which can have one
// or several contexts already.
func AppendExternalContexts(context interface{}, extraContexts ...string) []interface{} {
	return processor.AppendExternalContexts(context, extraContexts...)
}

// TransformBlankNode replaces blank node identifiers in the RDF statements.
// For example, transform from "_:c14n0" to "urn:bnid:_:c14n0".
func TransformBlankNode(row string) string {
	return processor.TransformBlankNode(row)
}
