/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	validCred1 = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/ext/type1"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "CredType1"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "s1": "custom subject 1"
  },

  "c1": "custom field 1",

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z"
}
`

	validCred2 = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/ext/type2"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential",
    "CredType2"
  ],
  "credentialSubject": {
    "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
    "s2": "custom subject 2"
  },

  "c2": "custom field 2",

  "issuer": {
    "id": "did:example:76e12ec712ebc6f1c221ebfeb1f",
    "name": "Example University"
  },

  "issuanceDate": "2010-01-01T19:23:24Z"
}`

	credMissingMandatoryFields = `
{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://www.w3.org/2018/credentials/examples/ext/type2"
  ],
  "id": "http://example.edu/credentials/1872",
  "type": [
    "VerifiableCredential"
  ]
}`
)

type CustomCredentialProducer struct {
	Accept func(cred *Credential) bool
	Apply  func(dataJSON []byte) (interface{}, error)
}

type Cred1 struct {
	Base    Credential
	Subject struct {
		ID                 string `json:"id,omitempty"`
		CustomSubjectField string `json:"s1,omitempty"`
	} `json:"credentialSubject,omitempty"`
	CustomField string `json:"c1,omitempty"`
}

type Cred2 struct {
	Base    Credential
	Subject struct {
		ID                 string `json:"id,omitempty"`
		CustomSubjectField string `json:"s2,omitempty"`
	} `json:"credentialSubject,omitempty"`
	CustomField string `json:"c2,omitempty"`
}

func Cred1Producer() CustomCredentialProducer {
	return CustomCredentialProducer{
		Apply: func(dataJSON []byte) (interface{}, error) {
			cred1 := &Cred1{}

			_, err := NewCredential(
				dataJSON,
				WithDecoders([]CredentialDecoder{func(dataJSON []byte, c *Credential) error {
					return json.Unmarshal(dataJSON, cred1)
				}}),
				WithTemplate(func() *Credential {
					return &cred1.Base
				}),
			)
			if err != nil {
				return nil, err
			}
			return cred1, nil
		},
		Accept: func(vc *Credential) bool {
			return hasContext(vc.Context, "https://www.w3.org/2018/credentials/examples/ext/type1") &&
				hasType(vc.Types, "CredType1")
		},
	}
}

func Cred2Producer() CustomCredentialProducer {
	return CustomCredentialProducer{
		Apply: func(dataJSON []byte) (interface{}, error) {
			cred2 := &Cred2{}

			_, err := NewCredential(
				dataJSON,
				WithDecoders([]CredentialDecoder{func(dataJSON []byte, c *Credential) error {
					return json.Unmarshal(dataJSON, cred2)
				}}),
				WithTemplate(func() *Credential {
					return &cred2.Base
				}),
			)
			if err != nil {
				return nil, err
			}
			return cred2, nil
		},
		Accept: func(vc *Credential) bool {
			return hasContext(vc.Context, "https://www.w3.org/2018/credentials/examples/ext/type2") &&
				hasType(vc.Types, "CredType2")
		},
	}
}

func decodeCredentials(dataJSON []byte, producers ...CustomCredentialProducer) (interface{}, error) {
	var (
		baseCred *Credential
		credErr  error
	)

	if baseCred, credErr = NewCredential(dataJSON); credErr != nil {
		return nil, fmt.Errorf("build base verifiable credential: %w", credErr)
	}

	for _, p := range producers {
		if p.Accept(baseCred) {
			var (
				customCred interface{}
				jsonErr    error
			)

			if customCred, jsonErr = p.Apply(dataJSON); jsonErr == nil {
				return customCred, nil
			}

			return nil, fmt.Errorf("error occurred when building custom verifiable credential: %w", jsonErr)
		}
	}

	// return base credential no producers accepted the dataJSON
	return baseCred, nil
}

func hasContext(allContexts []string, targetContext string) bool {
	for _, thatType := range allContexts {
		if thatType == targetContext {
			return true
		}
	}

	return false
}

func hasType(allTypes []string, targetType string) bool {
	for _, thatType := range allTypes {
		if thatType == targetType {
			return true
		}
	}

	return false
}

func TestCredentialExtensibilitySwitch(t *testing.T) {
	producers := []CustomCredentialProducer{Cred1Producer(), Cred2Producer()}

	i1, err := decodeCredentials([]byte(validCred1), producers...)
	require.NoError(t, err)
	require.IsType(t, &Cred1{}, i1)
	cred1, correct := i1.(*Cred1)
	require.True(t, correct)
	require.NotNil(t, cred1.Base)
	require.Equal(t, []string{"VerifiableCredential", "CredType1"}, cred1.Base.Types)
	require.Equal(t, "custom field 1", cred1.CustomField)
	require.Equal(t, "custom subject 1", cred1.Subject.CustomSubjectField)

	i2, err := decodeCredentials([]byte(validCred2), producers...)
	require.NoError(t, err)
	require.IsType(t, &Cred2{}, i2)
	cred2, correct := i2.(*Cred2)
	require.True(t, correct)
	require.NotNil(t, cred2.Base)
	require.Equal(t, []string{"VerifiableCredential", "CredType2"}, cred2.Base.Types)
	require.Equal(t, "custom field 2", cred2.CustomField)
	require.Equal(t, "custom subject 2", cred2.Subject.CustomSubjectField)

	i3, err := decodeCredentials([]byte(validCredential), producers...)
	require.NoError(t, err)
	require.IsType(t, &Credential{}, i3)

	_, err = decodeCredentials([]byte(credMissingMandatoryFields), producers...)
	require.Error(t, err)
	require.Contains(t, err.Error(), "build base verifiable credential")
}
