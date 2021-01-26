/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
)

const (
	format             = "application/n-quads"
	defaultAlgorithm   = "URDNA2015"
	handleNormalizeErr = "error while parsing N-Quads; invalid quad. line:"
)

var logger = log.New("aries-framework/json-ld-processor")

// ErrInvalidRDFFound is returned when normalized view contains invalid RDF.
var ErrInvalidRDFFound = errors.New("invalid JSON-LD context")

// processorOpts holds options for canonicalization of JSON LD docs.
type processorOpts struct {
	removeInvalidRDF bool
	validateRDF      bool
	documentLoader   ld.DocumentLoader
	externalContexts []string
}

// ProcessorOpts are the options for JSON LD operations on docs (like canonicalization or compacting).
type ProcessorOpts func(opts *processorOpts)

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalize document.
func WithRemoveAllInvalidRDF() ProcessorOpts {
	return func(opts *processorOpts) {
		opts.removeInvalidRDF = true
	}
}

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(loader ld.DocumentLoader) ProcessorOpts {
	return func(opts *processorOpts) {
		opts.documentLoader = loader
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(context ...string) ProcessorOpts {
	return func(opts *processorOpts) {
		opts.externalContexts = context
	}
}

// WithValidateRDF option validates result view and fails if any invalid RDF dataset found.
// This option will take precedence when used in conjunction with 'WithRemoveAllInvalidRDF' option.
func WithValidateRDF() ProcessorOpts {
	return func(opts *processorOpts) {
		opts.validateRDF = true
	}
}

// Processor is JSON-LD processor for aries.
// processing mode JSON-LD 1.0 {RFC: https://www.w3.org/TR/2014/REC-json-ld-20140116}
type Processor struct {
	algorithm     string
	defaultLoader ld.DocumentLoader
}

// NewProcessor returns new JSON-LD processor for aries.
func NewProcessor(algorithm string) *Processor {
	if algorithm == "" {
		return Default()
	}

	return &Processor{algorithm: algorithm, defaultLoader: createCachingDocumentLoader()}
}

// Default returns new JSON-LD processor with default RDF dataset algorithm.
func Default() *Processor {
	return &Processor{algorithm: defaultAlgorithm, defaultLoader: createCachingDocumentLoader()}
}

// GetCanonicalDocument returns canonized document of given json ld.
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...ProcessorOpts) ([]byte, error) {
	procOptions := p.prepareOpts(opts)

	if len(procOptions.externalContexts) > 0 {
		doc["@context"] = AppendExternalContexts(doc["@context"], procOptions.externalContexts...)
	}

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	proc := ld.NewJsonLdProcessor()

	view, err := proc.Normalize(doc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to normalize JSON-LD document: %w", err)
	}

	result, ok := view.(string)
	if !ok {
		return nil, fmt.Errorf("failed to normalize JSON-LD document, invalid view")
	}

	result, err = p.removeMatchingInvalidRDFs(result, procOptions)
	if err != nil {
		return nil, err
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

// Compact compacts given json ld object.
func (p *Processor) Compact(input, context map[string]interface{},
	opts ...ProcessorOpts) (map[string]interface{}, error) {
	procOptions := p.prepareOpts(opts)

	if context == nil {
		inputContext := input["@context"]

		if len(procOptions.externalContexts) > 0 {
			inputContext = AppendExternalContexts(inputContext, procOptions.externalContexts...)
			input["@context"] = inputContext
		}

		context = map[string]interface{}{"@context": inputContext}
	}

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	return ld.NewJsonLdProcessor().Compact(input, context, ldOptions)
}

// Frame makes a frame from the inputDoc using frameDoc.
func (p *Processor) Frame(inputDoc map[string]interface{}, frameDoc map[string]interface{},
	opts ...ProcessorOpts) (map[string]interface{}, error) {
	procOptions := p.prepareOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	proc := ld.NewJsonLdProcessor()

	// TODO Drop replacing duplicated IDs as soon as https://github.com/piprate/json-gold/issues/44 will be fixed.
	duplicatedIDs, err := getDuplicatedIDs(inputDoc, proc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("get duplicated ids: %w", err)
	}

	var inputDocCopy map[string]interface{}

	var randomIds map[string]string

	if len(duplicatedIDs) > 0 {
		inputDocCopy = copyMap(inputDoc)

		randomIds = make(map[string]string)

		visitJSONMap(inputDocCopy, func(key, id string) (string, bool) {
			if _, ok := duplicatedIDs[id]; !ok {
				return "", false
			}

			randomID := uuid.New().String()
			randomIds[randomID] = id

			return randomID, true
		})
	} else {
		inputDocCopy = inputDoc
	}

	ldOptions.OmitGraph = true

	framedInputDoc, err := proc.Frame(inputDocCopy, frameDoc, ldOptions)
	if err != nil {
		return nil, err
	}

	framedInputDoc["@context"] = frameDoc["@context"]

	if len(duplicatedIDs) == 0 {
		return framedInputDoc, nil
	}

	visitJSONMap(framedInputDoc, func(key, val string) (string, bool) {
		v, ok := randomIds[val]

		return v, ok
	})

	return framedInputDoc, nil
}

func copyMap(m map[string]interface{}) map[string]interface{} {
	cm := make(map[string]interface{})

	for k, v := range m {
		vm, ok := v.(map[string]interface{})
		if ok {
			cm[k] = copyMap(vm)
		} else {
			cm[k] = v
		}
	}

	return cm
}

func getDuplicatedIDs(doc map[string]interface{}, proc *ld.JsonLdProcessor, options *ld.JsonLdOptions) (
	map[string]bool, error) {
	expand, err := proc.Expand(doc, options)
	if err != nil {
		return nil, err
	}

	ids := make(map[string]bool)

	visitJSONArray(expand, func(key, val string) (string, bool) {
		if key == "@id" {
			if _, ok := ids[val]; ok {
				ids[val] = true
			} else {
				ids[val] = false
			}
		}

		return "", false
	})

	for k, v := range ids {
		if !v {
			delete(ids, k)
		}
	}

	return ids, nil
}

func visitJSONArray(a []interface{}, visitFunc func(key, val string) (string, bool)) {
	for i, v := range a {
		switch kv := v.(type) {
		case string:
			if newValue, ok := visitFunc("", kv); ok {
				a[i] = newValue
			}

		case []interface{}:
			visitJSONArray(kv, visitFunc)

		case map[string]interface{}:
			visitJSONMap(kv, visitFunc)
		}
	}
}

func visitJSONMap(m map[string]interface{}, visitFunc func(key, val string) (string, bool)) {
	for k, v := range m {
		switch kv := v.(type) {
		case string:
			if newID, ok := visitFunc(k, kv); ok {
				m[k] = newID
			}

		case []interface{}:
			visitJSONArray(kv, visitFunc)

		case map[string]interface{}:
			visitJSONMap(kv, visitFunc)
		}
	}
}

// removeMatchingInvalidRDFs validates normalized view to find any invalid RDF and
// returns filtered view after removing all invalid data except the ones given in rdfMatches argument.
// [Note : handling invalid RDF data, by following pattern https://github.com/digitalbazaar/jsonld.js/issues/199]
func (p *Processor) removeMatchingInvalidRDFs(view string, opts *processorOpts) (string, error) {
	if !opts.removeInvalidRDF && !opts.validateRDF {
		return view, nil
	}

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
	} else if opts.validateRDF {
		return "", ErrInvalidRDFFound
	}

	filteredView := strings.Join(filteredViews, "\n")

	logger.Debugf("Found invalid RDF dataset, Canonicalizing JSON-LD again after removing invalid data ")

	// all invalid RDF dataset from view are removed, re-generate
	return p.normalizeFilteredDataset(filteredView)
}

// normalizeFilteredDataset recreates json-ld from RDF view and
// returns normalized RDF dataset from recreated json-ld.
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

// prepareOpts prepare processorOpts from given CanonicalizationOpts arguments.
func (p *Processor) prepareOpts(opts []ProcessorOpts) *processorOpts {
	nOpts := &processorOpts{
		documentLoader: p.defaultLoader,
	}

	for _, opt := range opts {
		opt(nOpts)
	}

	return nOpts
}

func createCachingDocumentLoader() *ld.CachingDocumentLoader {
	cachingLoader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	for k, v := range jsonldCache {
		var m map[string]interface{}

		if err := json.Unmarshal([]byte(v), &m); err == nil {
			cachingLoader.AddDocument(k, m)
		}
	}

	return cachingLoader
}
