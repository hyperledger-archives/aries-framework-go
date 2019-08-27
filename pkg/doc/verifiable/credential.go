/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/xeipuuv/gojsonschema"
	errors "golang.org/x/xerrors"
)

const schema = `
{
  "required": [
    "@context",
    "type",
    "credentialSubject",
    "issuer",
    "issuanceDate"
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
      "additionalItems": {
        "type": "string"
      }
    },
    "id": {
      "type": "string",
      "format": "uri"
    },
    "type": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^VerifiableCredential$"
        }
      ],
      "additionalItems": {
        "type": "string"
      },
      "minItems": 2
    },
    "credentialSubject": {
      "anyOf": [
        {
          "type": "array"
        },
        {
          "type": "object"
        }
      ]
    },
    "issuer": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "object",
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "type": "string"
            }
          }
        }
      ]
    },
    "issuanceDate": {
      "$ref": "#/definitions/timestamp"
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
    },
    "expirationDate": {
      "$ref": "#/definitions/timestamp"
    },
    "credentialStatus": {
      "$ref": "#/definitions/typedID"
    },
    "credentialSchema": {
      "$ref": "#/definitions/typedID"
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "timestamp": {
      "type": "string",
      "pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
    },
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
          "type": "string"
        }
      }
    }
  }
}
`

var schemaLoader = gojsonschema.NewStringLoader(schema)

// Proof defines embedded proof of Verifiable Credential
type Proof struct {
	Type string `json:"type,omitempty"`
}

type typedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`
}

// Issuer of the Verifiable Credential
type Issuer struct {
	ID   string
	Name string
}

// Subject of the Verifiable Credential
type Subject interface{}

// CredentialStatus defines status of Verifiable Credential
type CredentialStatus typedID

// CredentialSchema defines a link to data schema which enforces a specific structure of Verifiable Credential.
type CredentialSchema typedID

// RefreshService provides a way to automatic refresh of expired Verifiable Credential
type RefreshService typedID

// Credential Verifiable Credential definition
type Credential struct {
	Context        []string
	ID             string
	Type           []string
	Subject        *Subject
	Issuer         Issuer
	Issued         *time.Time
	Expired        *time.Time
	Proof          *Proof
	Status         *CredentialStatus
	Schema         *CredentialSchema
	RefreshService *RefreshService
}

// rawCredential
type rawCredential struct {
	Context        []string          `json:"@context,omitempty"`
	ID             string            `json:"id,omitempty"`
	Type           []string          `json:"type,omitempty"`
	Subject        *Subject          `json:"credentialSubject,omitempty"`
	Issued         *time.Time        `json:"issuanceDate,omitempty"`
	Expired        *time.Time        `json:"expirationDate,omitempty"`
	Proof          *Proof            `json:"proof,omitempty"`
	Status         *CredentialStatus `json:"credentialStatus,omitempty"`
	Issuer         interface{}       `json:"issuer,omitempty"`
	Schema         *CredentialSchema `json:"credentialSchema,omitempty"`
	RefreshService *RefreshService   `json:"refreshService,omitempty"`
}

type issuerPlain struct {
	ID string `json:"issuer,omitempty"`
}

type compositeIssuer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type issuerComposite struct {
	CompositeIssuer compositeIssuer `json:"issuer,omitempty"`
}

// NewCredential creates an instance of Verifiable Credential by reading a JSON document from bytes
func NewCredential(data []byte) (*Credential, error) {
	// validate did document
	if err := validate(data); err != nil {
		return nil, err
	}

	raw := &rawCredential{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of Verifiable Credential bytes failed: %w", err)
	}

	issuerID, issuerName, err := issuerFromBytes(data)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of Verifiable Credential bytes failed: %w", err)
	}

	return &Credential{
		Context:        raw.Context,
		ID:             raw.ID,
		Type:           raw.Type,
		Subject:        raw.Subject,
		Issuer:         Issuer{ID: issuerID, Name: issuerName},
		Issued:         raw.Issued,
		Expired:        raw.Expired,
		Proof:          raw.Proof,
		Status:         raw.Status,
		Schema:         raw.Schema,
		RefreshService: raw.RefreshService,
	}, nil
}

func issuerFromBytes(data []byte) (string, string, error) {
	issuerPlain := &issuerPlain{}
	err := json.Unmarshal(data, &issuerPlain)
	if err == nil {
		return issuerPlain.ID, "", nil
	}

	issuerExtended := &issuerComposite{}
	err = json.Unmarshal(data, &issuerExtended)
	if err == nil {
		return issuerExtended.CompositeIssuer.ID, issuerExtended.CompositeIssuer.Name, nil
	}

	return "", "", errors.Errorf("Verifiable Credential's Issuer is not valid")

}

func issuerToSerialize(vc *Credential) interface{} {
	if vc.Issuer.Name != "" {
		return &compositeIssuer{ID: vc.Issuer.ID, Name: vc.Issuer.Name}
	}
	return vc.Issuer.ID
}

func validate(data []byte) error {
	// Validate that the Verifiable Credential conforms to the serialization of the Verifiable Credential data model (https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential)
	loader := gojsonschema.NewStringLoader(string(data))
	result, err := gojsonschema.Validate(schemaLoader, loader)
	if err != nil {
		return errors.Errorf("Validation of Verifiable Credential failed: %w", err)
	}

	if !result.Valid() {
		errMsg := "Verifiable Credential is not valid:\n"
		for _, desc := range result.Errors() {
			errMsg = errMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errors.New(errMsg)
	}
	return nil
}

// JSONBytes converts Verifiable Credential to JSON bytes
func (vc *Credential) JSONBytes() ([]byte, error) {
	rawCred := &rawCredential{
		Context:        vc.Context,
		ID:             vc.ID,
		Type:           vc.Type,
		Subject:        vc.Subject,
		Issued:         vc.Issued,
		Expired:        vc.Expired,
		Proof:          vc.Proof,
		Status:         vc.Status,
		Issuer:         issuerToSerialize(vc),
		Schema:         vc.Schema,
		RefreshService: vc.RefreshService,
	}

	byteCred, err := json.Marshal(rawCred)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of Verifiable Credential failed: %w", err)
	}

	return byteCred, nil
}
