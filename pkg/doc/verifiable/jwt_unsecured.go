/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// marshalUnsecuredJWT serializes JWT in unsecured form
func marshalUnsecuredJWT(headers map[string]string, claims interface{}) (string, error) {
	bHeader, err := json.Marshal(headers)
	if err != nil {
		return "", fmt.Errorf("serialize JOSE headers: %w", err)
	}

	bPayload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("serialize JWT claims: %w", err)
	}

	return fmt.Sprintf("%s.%s.",
			base64.RawURLEncoding.EncodeToString(bHeader),
			base64.RawURLEncoding.EncodeToString(bPayload)),
		nil
}

// unmarshalUnsecuredJWT unmarshals serialized JWT in unsecured form into jose headers and claims body.
func unmarshalUnsecuredJWT(rawJWT []byte) (joseHeaders map[string]string, bytesClaim []byte, err error) {
	parts := strings.Split(string(rawJWT), ".")

	if len(parts) != 3 {
		return nil, nil, errors.New("JWT format must have three parts")
	}

	if parts[2] != "" {
		return nil, nil, errors.New("unsecured JWT must have empty signature part")
	}

	bytesHeader, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, nil, err
	}

	headers := make(map[string]string)

	err = json.Unmarshal(bytesHeader, &headers)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal JSON-based JOSE headers: %w", err)
	}

	bytesPayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, nil, err
	}

	claims := make(map[string]interface{})

	err = json.Unmarshal(bytesPayload, &claims)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal JSON-based JWT claims: %w", err)
	}

	return headers, bytesPayload, nil
}

func isJWTUnsecured(data []byte) bool {
	parts := strings.Split(string(data), ".")

	isValidJSON := func(s string) bool {
		b, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return false
		}

		var j map[string]interface{}
		err = json.Unmarshal(b, &j)

		return err == nil
	}

	return len(parts) == 3 &&
		isValidJSON(parts[0]) &&
		isValidJSON(parts[1]) &&
		parts[2] == ""
}
