/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
)

const (
	// ContextURI is the required JSON-LD context for VCs and VPs.
	ContextURI = "https://www.w3.org/2018/credentials/v1"
	// ContextID is the non-fragment part of the JSON-LD schema ID for VCs and VPs.
	ContextID = "https://www.w3.org/2018/credentials"
	// VCType is the required Type for Verifiable Credentials.
	VCType = "VerifiableCredential"
	// VPType is the required Type for Verifiable Credentials.
	VPType = "VerifiablePresentation"
)

func compactJSONLD(doc string, opts *jsonldCredentialOpts, strict bool) error {
	docMap, err := toMap(doc)
	if err != nil {
		return fmt.Errorf("convert JSON-LD doc to map: %w", err)
	}

	jsonldProc := jsonld.Default()

	docCompactedMap, err := jsonldProc.Compact(docMap,
		nil, jsonld.WithDocumentLoader(opts.jsonldDocumentLoader),
		jsonld.WithExternalContext(opts.externalContext...))
	if err != nil {
		return fmt.Errorf("compact JSON-LD document: %w", err)
	}

	if strict && !mapsHaveSameStructure(docMap, docCompactedMap) {
		return errors.New("JSON-LD doc has different structure after compaction")
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
