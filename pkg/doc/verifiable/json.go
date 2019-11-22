/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
)

// marshalWithCustomFields marshals value merged with custom fields defined in the map into JSON bytes.
func marshalWithCustomFields(v interface{}, cf map[string]interface{}) ([]byte, error) {
	// Merge value and custom fields into the joint map.
	vm, err := mergeCustomFields(v, cf)
	if err != nil {
		return nil, err
	}

	// Marshal the joint map.
	return json.Marshal(vm)
}

// unmarshalWithCustomFields unmarshals JSON into value v and puts all JSON fields which do not belong to value
// into custom fields map cf.
func unmarshalWithCustomFields(data []byte, v interface{}, cf map[string]interface{}) error {
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

	// Copy only those entries which do not belong to the value (i.e. custom fields).
	for k, v := range af {
		if _, ok := vf[k]; !ok {
			cf[k] = v
		}
	}

	return nil
}

// mergeCustomFields converts value to the JSON-like map and merges it with custom fields map cf.
func mergeCustomFields(v interface{}, cf map[string]interface{}) (map[string]interface{}, error) {
	kf, err := toMap(v)
	if err != nil {
		return nil, err
	}

	// Supplement value map with custom fields.
	for k, v := range cf {
		if _, exists := kf[k]; !exists {
			kf[k] = v
		}
	}

	return kf, nil
}

func toMap(v interface{}) (map[string]interface{}, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var m map[string]interface{}

	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	return m, nil
}
