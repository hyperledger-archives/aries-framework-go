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
	removeRDFMatches []string
}

// CanonicalizationOpts are the options for canonicalization of JSON LD docs
type CanonicalizationOpts func(opts *normalizeOpts)

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalize document
func WithRemoveAllInvalidRDF() CanonicalizationOpts {
	return func(opts *normalizeOpts) {
		opts.removeInvalidRDF = true
	}
}

// WithRemoveInvalidRDF option for removing RDFs containing any one of the given matches
func WithRemoveInvalidRDF(matches ...string) CanonicalizationOpts {
	return func(opts *normalizeOpts) {
		opts.removeRDFMatches = matches
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
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...CanonicalizationOpts) ([]byte, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Algorithm = p.algorithm
	options.Format = format
	options.ProduceGeneralizedRdf = true

	view, err := proc.Normalize(doc, options)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	customOpts := prepareOpts(opts)

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	if customOpts.removeInvalidRDF || len(customOpts.removeRDFMatches) > 0 {
		result, err = p.removeMatchingInvalidRDFs(result, customOpts.removeRDFMatches...)
		if err != nil {
			return nil, fmt.Errorf("failed to normalize due to invalid RDF dataset: %w", err)
		}
	}

	return []byte(result), nil
}

// Compact compacts given json ld object
func (p *Processor) Compact(input, context interface{}, loader ld.DocumentLoader) (map[string]interface{}, error) {
	proc := ld.NewJsonLdProcessor()
	options := ld.NewJsonLdOptions("")
	options.ProcessingMode = ld.JsonLd_1_1
	options.Format = format
	options.ProduceGeneralizedRdf = true

	if loader != nil {
		options.DocumentLoader = loader
	}

	return proc.Compact(input, context, options)
}

// removeMatchingInvalidRDFs validates normalized view to find any invalid RDF and
// returns filtered view after removing all invalid data except the ones given in rdfMatches argument.
// [Note : handling invalid RDF data, by following pattern https://github.com/digitalbazaar/jsonld.js/issues/199]
func (p *Processor) removeMatchingInvalidRDFs(view string, rdfMatches ...string) (string, error) {
	views := strings.Split(view, "\n")

	var filteredViews []string

	var dirtyDataSet, foundInvalid bool

	for _, v := range views {
		_, err := ld.ParseNQuads(v)
		if err != nil {
			if !strings.Contains(err.Error(), handleNormalizeErr) {
				return "", err
			}

			foundInvalid = true

			if shouldSkipRDF(v, rdfMatches...) {
				continue
			}

			logger.Warnf("Invalid RDF dataset in canonized JSON-LD document. %s", v)

			dirtyDataSet = true
		}

		filteredViews = append(filteredViews, v)
	}

	if !foundInvalid {
		// clean RDF view, no need to regenerate
		return view, nil
	}

	filteredView := strings.Join(filteredViews, "\n")
	// not safe to re-generate RDF dataset from view containing invalid RDFs
	if dirtyDataSet {
		return filteredView, nil
	}

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

// shouldSkipRDF checks if given line of RDF view matches with any of the given matches
func shouldSkipRDF(v string, matches ...string) bool {
	if len(matches) == 0 {
		return true
	}

	for _, m := range matches {
		if strings.Contains(v, m) {
			return true
		}
	}

	return false
}

// prepareOpts prepare normalizeOpts from given CanonicalizationOpts arguments.
func prepareOpts(opts []CanonicalizationOpts) *normalizeOpts {
	nOpts := &normalizeOpts{}
	// apply opts
	for _, opt := range opts {
		opt(nOpts)
	}

	return nOpts
}
