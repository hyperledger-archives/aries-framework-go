/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jsonld

import (
	"fmt"
	"regexp"
	"strconv"
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

// nolint:gochecknoglobals
var (
	invalidRDFLinePattern = regexp.MustCompile("[0-9]*$")
)

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
func (p *Processor) GetCanonicalDocument(doc map[string]interface{}) ([]byte, error) {
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

	result, err := p.validateView(view.(string))
	if err != nil {
		return nil, fmt.Errorf("failed to normalize due to invalid RDF dataset: %w", err)
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

// validateView validates normalized view to find any invalid RDF. If found then it discards that data
// and try again recursively until validation is passed and returns filtered view after removing all invalid data.
// [Note : handling invalid RDF data, by following pattern https://github.com/digitalbazaar/jsonld.js/issues/199]
func (p *Processor) validateView(view string) (string, error) {
	_, err := ld.ParseNQuads(view)
	if err != nil {
		if !strings.Contains(err.Error(), handleNormalizeErr) {
			return "", err
		}

		lineNumber, e := findLineNumber(err)
		if e != nil {
			return "", fmt.Errorf("failed to locate invalid RDF data:%w", e)
		}

		logger.Warnf("Found invalid data in normalized JSON-LD, removing invalid data at line number %d", lineNumber)

		return p.validateView(removeQuad(view, lineNumber-1))
	}

	return view, nil
}

// removeQuad removes quad from given index of view
func removeQuad(view string, index int) string {
	lines := strings.Split(view, "\n")
	return strings.Join(append(lines[:index], lines[index+1:]...), "\n")
}

// findLineNumber finds problematic line number from error
func findLineNumber(err error) (int, error) {
	s := invalidRDFLinePattern.FindString(err.Error())

	i, err := strconv.Atoi(s)
	if err != nil {
		return -1, fmt.Errorf("unable to locate invalid RDF data line number: %w", err)
	}

	return i, nil
}
