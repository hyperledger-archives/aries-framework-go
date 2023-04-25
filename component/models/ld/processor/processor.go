/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package processor

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/log"
	"github.com/hyperledger/aries-framework-go/component/models/util/maphelpers"
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
	frameBlankNodes  bool
	validateRDF      bool
	documentLoader   ld.DocumentLoader
	externalContexts []string
}

// Opts are the options for JSON LD operations on docs (like canonicalization or compacting).
type Opts func(opts *processorOpts)

// WithRemoveAllInvalidRDF option for removing all invalid RDF dataset from normalize document.
func WithRemoveAllInvalidRDF() Opts {
	return func(opts *processorOpts) {
		opts.removeInvalidRDF = true
	}
}

// WithFrameBlankNodes option for transforming blank node identifiers into nodes.
// For example, _:c14n0 is transformed into <urn:bnid:_:c14n0>.
func WithFrameBlankNodes() Opts {
	return func(opts *processorOpts) {
		opts.frameBlankNodes = true
	}
}

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(loader ld.DocumentLoader) Opts {
	return func(opts *processorOpts) {
		opts.documentLoader = loader
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(context ...string) Opts {
	return func(opts *processorOpts) {
		opts.externalContexts = context
	}
}

// WithValidateRDF option validates result view and fails if any invalid RDF dataset found.
// This option will take precedence when used in conjunction with 'WithRemoveAllInvalidRDF' option.
func WithValidateRDF() Opts {
	return func(opts *processorOpts) {
		opts.validateRDF = true
	}
}

// Processor is JSON-LD processor for aries.
// processing mode JSON-LD 1.0 {RFC: https://www.w3.org/TR/2014/REC-json-ld-20140116}
type Processor struct {
	algorithm string
}

// NewProcessor returns new JSON-LD processor for aries.
func NewProcessor(algorithm string) *Processor {
	if algorithm == "" {
		return Default()
	}

	return &Processor{algorithm}
}

// Default returns new JSON-LD processor with default RDF dataset algorithm.
func Default() *Processor {
	return &Processor{defaultAlgorithm}
}

// GetCanonicalDocument returns canonized document of given json ld.
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}, opts ...Opts) ([]byte, error) {
	procOptions := prepareOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	if len(procOptions.externalContexts) > 0 {
		doc["@context"] = AppendExternalContexts(doc["@context"], procOptions.externalContexts...)
	}

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
	opts ...Opts) (map[string]interface{}, error) {
	procOptions := prepareOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	if context == nil {
		inputContext := input["@context"]

		if len(procOptions.externalContexts) > 0 {
			inputContext = AppendExternalContexts(inputContext, procOptions.externalContexts...)
			input["@context"] = inputContext
		}

		context = map[string]interface{}{"@context": inputContext}
	}

	return ld.NewJsonLdProcessor().Compact(input, context, ldOptions)
}

// Frame makes a frame from the inputDoc using frameDoc.
func (p *Processor) Frame(inputDoc map[string]interface{}, frameDoc map[string]interface{},
	opts ...Opts) (map[string]interface{}, error) {
	procOptions := prepareOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.OmitGraph = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	proc := ld.NewJsonLdProcessor()

	hasBlankBaseID := false
	if checkID, ok := inputDoc["id"]; !ok || checkID == "" {
		hasBlankBaseID = true
		inputDoc["id"] = fmt.Sprintf("urn:uuid:%s", uuid.New().String())
		frameDoc["id"] = inputDoc["id"]
	}

	// TODO Drop replacing duplicated IDs as soon as https://github.com/piprate/json-gold/issues/44 will be fixed.
	inputDocCopy, randomIds, err := removeDuplicateIDs(inputDoc, proc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("removing duplicate ids failed: %w", err)
	}

	inputDocCopy, err = p.transformBlankNodes(inputDocCopy, opts...)
	if err != nil {
		return nil, fmt.Errorf("transforming frame input failed: %w", err)
	}

	framedInputDoc, err := proc.Frame(inputDocCopy, frameDoc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("framing failed: %w", err)
	}

	framedInputDoc["@context"] = frameDoc["@context"]

	if hasBlankBaseID {
		delete(framedInputDoc, "id")
		delete(frameDoc, "id")
	}

	// TODO Drop replacing duplicated IDs as soon as https://github.com/piprate/json-gold/issues/44 will be fixed.
	if len(randomIds) == 0 {
		return framedInputDoc, nil
	}

	visitJSONMap(framedInputDoc, func(key, val string) (string, bool) {
		v, ok := randomIds[val]

		return v, ok
	})

	return framedInputDoc, nil
}

func removeDuplicateIDs(inputDoc map[string]interface{}, proc *ld.JsonLdProcessor,
	options *ld.JsonLdOptions) (map[string]interface{}, map[string]string, error) {
	duplicatedIDs, err := getDuplicatedIDs(inputDoc, proc, options)
	if err != nil {
		return nil, nil, fmt.Errorf("get duplicated ids: %w", err)
	}

	var inputDocCopy map[string]interface{}

	var randomIds map[string]string

	if len(duplicatedIDs) > 0 {
		inputDocCopy = maphelpers.CopyMap(inputDoc)

		randomIds = make(map[string]string)

		visitJSONMap(inputDocCopy, func(key, id string) (string, bool) {
			if _, ok := duplicatedIDs[id]; !ok {
				return "", false
			}

			randomID := fmt.Sprintf("urn:uuid:%s", uuid.New().String())
			randomIds[randomID] = id

			return randomID, true
		})
	} else {
		inputDocCopy = inputDoc
	}

	return inputDocCopy, randomIds, nil
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
	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Algorithm = p.algorithm
	ldOptions.Format = format

	proc := ld.NewJsonLdProcessor()

	filteredJSONLd, err := proc.FromRDF(view, ldOptions)
	if err != nil {
		return "", err
	}

	result, err := proc.Normalize(filteredJSONLd, ldOptions)
	if err != nil {
		return "", err
	}

	return result.(string), nil
}

func fromRDF(docStatements []string, context interface{},
	opts ...Opts) (map[string]interface{}, error) {
	procOptions := prepareOpts(opts)

	ldOptions := ld.NewJsonLdOptions("")
	ldOptions.ProcessingMode = ld.JsonLd_1_1
	ldOptions.Format = format
	ldOptions.ProduceGeneralizedRdf = true
	ldOptions.DocumentLoader = procOptions.documentLoader

	doc := strings.Join(docStatements, "\n")
	proc := ld.NewJsonLdProcessor()

	transformedDoc, err := proc.FromRDF(doc, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("rdf processing failed: %w", err)
	}

	transformedDocMap, err := proc.Compact(transformedDoc, context, ldOptions)
	if err != nil {
		return nil, fmt.Errorf("compacting failed: %w", err)
	}

	return transformedDocMap, nil
}

// prepareOpts prepare processorOpts from given CanonicalizationOpts arguments.
func prepareOpts(opts []Opts) *processorOpts {
	procOpts := &processorOpts{}

	for _, opt := range opts {
		opt(procOpts)
	}

	return procOpts
}

func (p *Processor) transformBlankNodes(docMap map[string]interface{},
	opts ...Opts) (map[string]interface{}, error) {
	procOptions := prepareOpts(opts)

	if !procOptions.frameBlankNodes {
		return docMap, nil
	}

	docBytes, err := p.GetCanonicalDocument(docMap, opts...)
	if err != nil {
		return nil, err
	}

	rows := splitMessageIntoLines(string(docBytes))

	for i, row := range rows {
		rows[i] = TransformBlankNode(row)
	}

	return fromRDF(rows, docMap["@context"], opts...)
}

func splitMessageIntoLines(msg string) []string {
	rows := strings.Split(msg, "\n")

	msgs := make([]string, 0, len(rows))

	for i := range rows {
		if strings.TrimSpace(rows[i]) != "" {
			msgs = append(msgs, rows[i])
		}
	}

	return msgs
}

// TransformBlankNode replaces blank node identifiers in the RDF statements.
// For example, transform from "_:c14n0" to "urn:bnid:_:c14n0".
func TransformBlankNode(row string) string {
	prefixIndex := strings.Index(row, "_:c14n")
	if prefixIndex < 0 {
		return row
	}

	sepIndex := strings.Index(row[prefixIndex:], " ")
	if sepIndex < 0 {
		sepIndex = len(row)
	} else {
		sepIndex += prefixIndex
	}

	prefix := row[:prefixIndex]
	blankNode := row[prefixIndex:sepIndex]
	suffix := row[sepIndex:]

	return fmt.Sprintf("%s<urn:bnid:%s>%s", prefix, blankNode, suffix)
}
