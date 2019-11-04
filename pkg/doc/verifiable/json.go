/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
)

// marshalWithExtraFields marshals value merged with extra fields defined in the map into JSON.
func marshalWithExtraFields(v interface{}, ef map[string]interface{}) ([]byte, error) {
	// Convert value into a JSON map of known fields.
	kf, err := mergeExtraFields(v, ef)
	if err != nil {
		return nil, err
	}

	// Marshal extended known fields map.
	return json.Marshal(kf)
}

// unmarshalWithExtraFields unmarshals JSON into value v and puts all JSON fields which do not belong to value
// into extra fields map ef.
func unmarshalWithExtraFields(data []byte, v interface{}, ef map[string]interface{}) error {
	err := json.Unmarshal(data, v)
	if err != nil {
		return err
	}

	// Collect value fields map.
	vData, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var vf map[string]interface{}
	err = json.Unmarshal(vData, &vf)
	if err != nil {
		return err
	}

	// Collect all fields map.
	var af map[string]interface{}
	err = json.Unmarshal(data, &af)
	if err != nil {
		return err
	}

	// Copy only those entries which do not belong to the value (i.e. extra fields).
	for k, v := range af {
		if _, ok := vf[k]; !ok {
			ef[k] = v
		}
	}

	return nil
}

// mergeExtraFields converts value to the JSON-like map and merges it with extra fields map.
func mergeExtraFields(v interface{}, ef map[string]interface{}) (map[string]interface{}, error) {
	// Convert raw credential into a JSON map of known fields.
	rcBytes, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var kf map[string]interface{}
	err = json.Unmarshal(rcBytes, &kf)
	if err != nil {
		return nil, err
	}

	// Supplement value map with extra fields.
	for k, v := range ef {
		if _, exists := kf[k]; !exists {
			kf[k] = v
		}
	}

	return kf, nil
}
