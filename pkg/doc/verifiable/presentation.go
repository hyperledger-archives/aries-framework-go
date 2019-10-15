/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/xeipuuv/gojsonschema"
)

const basePresentationSchema = `
{
  "required": [
    "@context",
    "type",
    "verifiableCredential"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^https://www.w3.org/2018/credentials/v1$"
        }
      ],
      "uniqueItems": true,
      "additionalItems": {
        "oneOf": [
          {
            "type": "object"
          },
          {
            "type": "string"
          }
        ]
      }
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "pattern": "^VerifiablePresentation$"
            }
          ],
          "minItems": 1
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ],
      "additionalItems": {
        "type": "string"
      }
    },
    "verifiableCredential": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        },
        {
          "type": "string"
        }
      ]
    },
    "holder": {
      "type": "string",
      "format": "uri"
    },
    "proof": {
      "anyOf": [
        {
          "type": "array",
          "items": [
            {
              "$ref": "#/definitions/proof"
            }
          ]
        },
        {
          "$ref": "#/definitions/proof"
        }
      ]
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "anyOf": [
            {
              "type": "string"
            },
            {
              "type": "array",
              "items": {
                "type": "string"
              }
            }
          ]
        }
      }
    },
    "proof": {
      "type": "object",
      "required": [
        "type"
      ],
      "properties": {
        "type": {
          "type": "string"
        }
      }
    }
  }
}
`

//nolint:gochecknoglobals
var basePresentationSchemaLoader = gojsonschema.NewStringLoader(basePresentationSchema)

// PresentationCredential defines raw Verifiable Credential enclosed into Presentation.
type PresentationCredential []byte

// Presentation Verifiable Presentation base data model definition
type Presentation struct {
	Context        []interface{}
	ID             string
	Type           interface{}
	Credential     interface{}
	Holder         string
	Proof          Proof
	RefreshService *RefreshService
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	byteCred, err := json.Marshal(vp.raw())
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential failed: %w", err)
	}

	return byteCred, nil
}

// Credentials provides Verifiable Credentials enclosed into Presentation in raw byte array format.
func (vp *Presentation) Credentials() ([]PresentationCredential, error) {
	marshalSingleCredFn := func(cred interface{}) (PresentationCredential, error) {
		credBytes, err := json.Marshal(cred)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal credentials from presentation: %w", err)
		}
		return credBytes, nil
	}

	switch cred := vp.Credential.(type) {
	case []interface{}:
		// 1 or more credentials
		creds := make([]PresentationCredential, len(cred))
		for i := range cred {
			c, err := marshalSingleCredFn(cred[i])
			if err != nil {
				return nil, err
			}
			creds[i] = c
		}
		return creds, nil
	default:
		// single credential
		c, err := marshalSingleCredFn(cred)
		if err != nil {
			return nil, err
		}
		return []PresentationCredential{c}, nil
	}
}

func (vp *Presentation) raw() *rawPresentation {
	return &rawPresentation{
		Context:        vp.Context,
		ID:             vp.ID,
		Type:           vp.Type,
		Credential:     vp.Credential,
		Holder:         vp.Holder,
		Proof:          vp.Proof,
		RefreshService: vp.RefreshService,
	}
}

// rawPresentation is a basic verifiable credential
type rawPresentation struct {
	Context        []interface{}   `json:"@context,omitempty"`
	ID             string          `json:"id,omitempty"`
	Type           interface{}     `json:"type,omitempty"`
	Credential     interface{}     `json:"verifiableCredential,omitempty"`
	Holder         string          `json:"holder,omitempty"`
	Proof          Proof           `json:"proof,omitempty"`
	RefreshService *RefreshService `json:"refreshService,omitempty"`
}

// NewPresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
func NewPresentation(vpData []byte) (*Presentation, error) {
	vpDataDecoded, vpRaw, err := decodeRawPresentation(vpData)
	if err != nil {
		return nil, err
	}

	err = validatePresentation(vpDataDecoded)
	if err != nil {
		return nil, err
	}

	vp := &Presentation{
		Context:        vpRaw.Context,
		ID:             vpRaw.ID,
		Type:           vpRaw.Type,
		Credential:     vpRaw.Credential,
		Holder:         vpRaw.Holder,
		Proof:          vpRaw.Proof,
		RefreshService: vpRaw.RefreshService,
	}

	return vp, nil
}

func validatePresentation(data []byte) error {
	loader := gojsonschema.NewStringLoader(string(data))
	result, err := gojsonschema.Validate(basePresentationSchemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential failed: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable presentation")
		return errors.New(errMsg)
	}

	return nil
}

func decodeRawPresentation(vpData []byte) ([]byte, *rawPresentation, error) {
	// unmarshal VP from JSON
	raw := new(rawPresentation)
	err := json.Unmarshal(vpData, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshalling of verifiable presentation failed: %w", err)
	}

	// check that embedded proof is present, if not, it's not a verifiable credential
	if raw.Proof == nil {
		return nil, nil, errors.New("embedded proof is missing")
	}

	return vpData, raw, nil
}
