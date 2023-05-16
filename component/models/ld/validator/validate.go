/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package validator

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/models/ld/processor"
	"github.com/hyperledger/aries-framework-go/component/models/util/json"
)

type validateOpts struct {
	strict               bool
	jsonldDocumentLoader ld.DocumentLoader
	externalContext      []string
	contextURIPositions  []string
}

// ValidateOpts sets jsonld validation options.
type ValidateOpts func(opts *validateOpts)

// WithDocumentLoader option is for passing custom JSON-LD document loader.
func WithDocumentLoader(jsonldDocumentLoader ld.DocumentLoader) ValidateOpts {
	return func(opts *validateOpts) {
		opts.jsonldDocumentLoader = jsonldDocumentLoader
	}
}

// WithExternalContext option is for definition of external context when doing JSON-LD operations.
func WithExternalContext(externalContext []string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.externalContext = externalContext
	}
}

// WithStrictValidation sets if strict validation should be used.
func WithStrictValidation(checkStructure bool) ValidateOpts {
	return func(opts *validateOpts) {
		opts.strict = checkStructure
	}
}

// WithStrictContextURIPosition sets strict validation of URI position within context property.
// The index of uri in underlying slice represents the position of given uri in @context array.
// Can be used for verifiable credential base context validation.
func WithStrictContextURIPosition(uri string) ValidateOpts {
	return func(opts *validateOpts) {
		opts.contextURIPositions = append(opts.contextURIPositions, uri)
	}
}

func getValidateOpts(options []ValidateOpts) *validateOpts {
	result := &validateOpts{
		strict: true,
	}

	for _, opt := range options {
		opt(result)
	}

	return result
}

// ValidateJSONLD validates jsonld structure.
func ValidateJSONLD(doc string, options ...ValidateOpts) error {
	docMap, err := json.ToMap(doc)
	if err != nil {
		return fmt.Errorf("convert JSON-LD doc to map: %w", err)
	}

	return ValidateJSONLDMap(docMap, options...)
}

// ValidateJSONLDMap validates jsonld structure.
func ValidateJSONLDMap(docMap map[string]interface{}, options ...ValidateOpts) error {
	opts := getValidateOpts(options)

	jsonldProc := processor.Default()

	docCompactedMap, err := jsonldProc.Compact(docMap,
		nil, processor.WithDocumentLoader(opts.jsonldDocumentLoader),
		processor.WithExternalContext(opts.externalContext...))
	if err != nil {
		return fmt.Errorf("compact JSON-LD document: %w", err)
	}

	if opts.strict && !mapsHaveSameStructure(docMap, docCompactedMap) {
		return errors.New("JSON-LD doc has different structure after compaction")
	}

	err = validateContextURIPosition(opts.contextURIPositions, docMap)
	if err != nil {
		return fmt.Errorf("validate context URI position: %w", err)
	}

	return nil
}

func validateContextURIPosition(contextURIPositions []string, docMap map[string]interface{}) error {
	if len(contextURIPositions) == 0 {
		return nil
	}

	var docContexts []interface{}

	switch t := docMap["@context"].(type) {
	case string:
		docContexts = append(docContexts, t)
	case []interface{}:
		docContexts = append(docContexts, t...)
	}

	if len(docContexts) < len(contextURIPositions) {
		return errors.New("doc context URIs amount mismatch")
	}

	for position, uri := range contextURIPositions {
		docURI, ok := docContexts[position].(string)
		if !ok {
			return fmt.Errorf("unsupported URI type %s", reflect.TypeOf(docContexts[position]).String())
		}

		if !strings.EqualFold(docURI, uri) {
			return fmt.Errorf("invalid context URI on position %d, %s expected", position, uri)
		}
	}

	return nil
}

func mapsHaveSameStructure(originalMap, compactedMap map[string]interface{}) bool {
	original := compactMap(originalMap)
	compacted := compactMap(compactedMap)

	if reflect.DeepEqual(original, compacted) {
		return true
	}

	if len(original) != len(compacted) {
		return false
	}

	for k, v1 := range original {
		v1Map, isMap := v1.(map[string]interface{})
		if !isMap {
			continue
		}

		v2, present := compacted[k]
		if !present { // special case - the name of the map was mapped, cannot guess what's a new name
			continue
		}

		v2Map, isMap := v2.(map[string]interface{})
		if !isMap {
			return false
		}

		if !mapsHaveSameStructure(v1Map, v2Map) {
			return false
		}
	}

	return true
}

func compactMap(m map[string]interface{}) map[string]interface{} {
	mCopy := make(map[string]interface{})

	for k, v := range m {
		// ignore context
		if k == "@context" {
			continue
		}

		vNorm := compactValue(v)

		switch kv := vNorm.(type) {
		case []interface{}:
			mCopy[k] = compactSlice(kv)

		case map[string]interface{}:
			mCopy[k] = compactMap(kv)

		default:
			mCopy[k] = vNorm
		}
	}

	return mCopy
}

func compactSlice(s []interface{}) []interface{} {
	sCopy := make([]interface{}, len(s))

	for i := range s {
		sItem := compactValue(s[i])

		switch sItem := sItem.(type) {
		case map[string]interface{}:
			sCopy[i] = compactMap(sItem)

		default:
			sCopy[i] = sItem
		}
	}

	return sCopy
}

func compactValue(v interface{}) interface{} {
	switch cv := v.(type) {
	case []interface{}:
		// consists of only one element
		if len(cv) == 1 {
			return compactValue(cv[0])
		}

		return cv

	case map[string]interface{}:
		// contains "id" element only
		if len(cv) == 1 {
			if _, ok := cv["id"]; ok {
				return cv["id"]
			}
		}

		return cv

	default:
		return cv
	}
}
