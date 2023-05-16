/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package json

import (
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
)

// MarshalWithCustomFields marshals value merged with custom fields defined in the map into JSON bytes.
func MarshalWithCustomFields(v interface{}, cf map[string]interface{}) ([]byte, error) {
	return jsonutil.MarshalWithCustomFields(v, cf)
}

// UnmarshalWithCustomFields unmarshals JSON into value v and puts all JSON fields which do not belong to value
// into custom fields map cf.
func UnmarshalWithCustomFields(data []byte, v interface{}, cf map[string]interface{}) error {
	return jsonutil.UnmarshalWithCustomFields(data, v, cf)
}

// MergeCustomFields converts value to the JSON-like map and merges it with custom fields map cf.
func MergeCustomFields(v interface{}, cf map[string]interface{}) (map[string]interface{}, error) {
	return jsonutil.MergeCustomFields(v, cf)
}

// ToMap convert object, string or bytes to json object represented by map.
func ToMap(v interface{}) (map[string]interface{}, error) {
	return jsonutil.ToMap(v)
}

// ToMaps convert array to array of json objects.
func ToMaps(v []interface{}) ([]map[string]interface{}, error) {
	return jsonutil.ToMaps(v)
}
