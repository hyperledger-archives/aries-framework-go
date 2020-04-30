/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	format             = "application/n-quads"
	defaultAlgorithm   = "URDNA2015"
	handleNormalizeErr = "Error while parsing N-Quads; invalid quad. line:"
)

var logger = log.New("aries-framework/json-ld-processor")

// normalizeOpts holds options for canonicalization of JSON LD docs
type normalizeOpts struct {
	removeInvalidRDF bool
	documentLoader   ld.DocumentLoader
	externalContexts []string
}

// ProcessorOpts are the options for JSON LD operations on docs (like canonicalization or compacting).
type ProcessorOpts func(opts *normalizeOpts)

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalize document
func WithRemoveAllInvalidRDF() ProcessorOpts {
	return func(opts *normalizeOpts) {
		opts.removeInvalidRDF = true
	}
}

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(loader ld.DocumentLoader) ProcessorOpts {
	return func(opts *normalizeOpts) {
		opts.documentLoader = loader
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(context ...string) ProcessorOpts {
	return func(opts *normalizeOpts) {
		opts.externalContexts = context
	}
}

// Processor is JSON-LD processor for aries.
// processing mode JSON-LD 1.0 {RFC: https://www.w3.org/TR/2014/REC-json-ld-20140116}
type Processor struct {
	algorithm string
}

// NewProcessor returns new JSON-LD processor for aries
func NewProcessor(algorithm string) *Processor {
	if algorithm == "" {
		return Default()
	}

	return &Processor{algorithm}
}

// Default returns new JSON-LD processor with default RDF dataset algorithm
func Default() *Processor {
	return &Processor{defaultAlgorithm}
}

// GetCanonicalDocument returns canonized document of given json ld
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...ProcessorOpts) ([]byte, error) {
	procOptions := prepareOpts(opts)

	proc := ld.NewJsonLdProcessor()
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true

	if procOptions.documentLoader != nil {
		ldOptions.DocumentLoader = procOptions.documentLoader
	}

	if len(procOptions.externalContexts) > 0 {
		doc["@context"] = AppendExternalContexts(doc["@context"], procOptions.externalContexts...)
	}

	view, err := proc.Normalize(doc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	if procOptions.removeInvalidRDF {
		result, err = p.removeMatchingInvalidRDFs(result)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize due to invalid RDF dataset: %w", err)
		}
	}

	return []byte(result), nil
}

// AppendExternalContexts appends external context(s) to the JSON-LD context which can have one
// or several contexts already.
func AppendExternalContexts(context interface{}, extraContexts ...string) []interface{} {
	var contexts []interface{}

	switch c := context.(type) {
	case string:
		contexts = append(contexts, c)
	case []interface{}:
		contexts = append(contexts, c...)
	}

	for i := range extraContexts {
		contexts = append(contexts, extraContexts[i])
	}

	return contexts
}

// Compact compacts given json ld object
func (p *Processor) Compact(input, context map[string]interface{},
	opts ...ProcessorOpts) (map[string]interface{}, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Format = format
	options.ProduceGeneralizedRdf = true

	procOptions := prepareOpts(opts)

	if procOptions.documentLoader != nil {
		options.DocumentLoader = procOptions.documentLoader
	}

	if context == nil {
		inputContext := input["@context"]

		if len(procOptions.externalContexts) > 0 {
			inputContext = AppendExternalContexts(inputContext, procOptions.externalContexts...)
			input["@context"] = inputContext
		}

		context = map[string]interface{}{"@context": inputContext}
	}

	return proc.Compact(input, context, options)
}

// removeMatchingInvalidRDFs validates normalized view to find any invalid RDF and
// returns filtered view after removing all invalid data except the ones given in rdfMatches argument.
// [Note : handling invalid RDF data, by following pattern https://github.com/digitalbazaar/jsonld.js/issues/199]
func (p *Processor) removeMatchingInvalidRDFs(view string) (string, error) {
	views := strings.Split(view, "\n")

	var filteredViews []string

	var foundInvalid bool

	for _, v := range views {
		_, err := ld.ParseNQuads(v)
		if err != nil {
			if !strings.Contains(err.Error(), handleNormalizeErr) {
				return "", err
			}

			foundInvalid = true

			continue
		}

		filteredViews = append(filteredViews, v)
	}

	if !foundInvalid {
		// clean RDF view, no need to regenerate
		return view, nil
	}

	filteredView := strings.Join(filteredViews, "\n")

	logger.Debugf("Found invalid RDF dataset, Canonicalizing JSON-LD again after removing invalid data ")

	// all invalid RDF dataset from view are removed, re-generate
	return p.normalizeFilteredDataset(filteredView)
}

// normalizeFilteredDataset recreates json-ld from RDF view and
// returns normalized RDF dataset from recreated json-ld
func (p *Processor) normalizeFilteredDataset(view string) (string, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Algorithm = p.algorithm
	options.Format = format

	filteredJSONLd, err := proc.FromRDF(view, options)
	if err != nil {
		return "", err
	}

	result, err := proc.Normalize(filteredJSONLd, options)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

// prepareOpts prepare normalizeOpts from given CanonicalizationOpts arguments.
func prepareOpts(opts []ProcessorOpts) *normalizeOpts {
	nOpts := &normalizeOpts{}
	// apply opts
	for _, opt := range opts {
		opt(nOpts)
	}

	return nOpts
}
