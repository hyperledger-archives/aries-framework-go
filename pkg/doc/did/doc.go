/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/xeipuuv/gojsonschema"
	errors "golang.org/x/xerrors"
)

const (
	jsonldType         = "type"
	jsonldID           = "id"
	jsonldServicePoint = "serviceEndpoint"
	jsonldController   = "controller"

	// various public key encodings
	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyHex    = "publicKeyHex"
	jsonldPublicKeyPem    = "publicKeyPem"
	schema                = `{
  "required": [
    "@context",
    "id"
  ],
  "properties": {
    "@context": {
      "type": "array",
      "items": [
        {
          "type": "string",
          "pattern": "^https://w3id.org/did/v1$"
        }
      ],
      "additionalItems": {
        "type": "string",
        "format": "uri"
      }
    },
    "id": {
      "type": "string"
    },
    "publicKey": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/publicKey"
      }
    },
    "authentication": {
      "type": "array",
      "items": {
        "oneOf": [
          {
            "$ref": "#/definitions/publicKey"
          },
          {
            "type": "string"
          }
        ]
      }
    },
    "service": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/service"
      }
    },
    "created": {
      "type": "string",
      "pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
    },
    "updated": {
      "type": "string",
      "pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
    },
    "proof": {
      "type": "object",
      "required": [ "type", "creator", "created", "signatureValue"],
      "properties": {
        "type": {
          "type": "string",
          "format": "uri-reference"
        },
        "creator": {
          "type": "string",
          "format": "uri-reference"
        },
        "created": {
          "type": "string",
          "pattern": "\\d{4}-[01]\\d-[0-3]\\dT[0-2]\\d:[0-5]\\d:[0-5]\\dZ"
        },
        "signatureValue": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        }
  }
    }
  },
  "definitions": {
    "publicKey": {
      "required": [
        "id",
        "type",
        "controller"
      ],
      "type": "object",
      "minProperties": 4,
      "maxProperties": 4,
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "controller": {
          "type": "string"
        }
      }
    },
    "service": {
      "required": [
        "id",
        "type",
        "serviceEndpoint"
      ],
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "serviceEndpoint": {
          "type": "string",
          "format": "uri"
        }
      }
    }
  }
}`
)

var schemaLoader = gojsonschema.NewStringLoader(schema)

// Doc DID Document definition
type Doc struct {
	Context        []string
	ID             string
	PublicKey      []PublicKey
	Service        []Service
	Authentication []VerificationMethod
	Created        *time.Time
	Updated        *time.Time
	Proof          *Proof
}

// PublicKey DID doc public key
type PublicKey struct {
	ID         string
	Type       string
	Controller string
	Value      []byte
}

// Service DID doc service
type Service struct {
	ID              string
	Type            string
	ServiceEndpoint string
	Properties      map[string]interface{}
}

// VerificationMethod authentication verification method
type VerificationMethod struct {
	PublicKey PublicKey
}

type rawDoc struct {
	Context        []string                 `json:"@context,omitempty"`
	ID             string                   `json:"id,omitempty"`
	PublicKey      []map[string]interface{} `json:"publicKey,omitempty"`
	Service        []map[string]interface{} `json:"service,omitempty"`
	Authentication []interface{}            `json:"authentication,omitempty"`
	Created        *time.Time               `json:"created,omitempty"`
	Updated        *time.Time               `json:"updated,omitempty"`
	Proof          *Proof                   `json:"proof,omitempty"`
}

// Proof is cryptographic proof of the integrity of the DID Document
type Proof struct {
	Type           string     `json:"type,omitempty"`
	Created        *time.Time `json:"created,omitempty"`
	Creator        string     `json:"creator,omitempty"`
	SignatureValue string     `json:"signatureValue,omitempty"`
	Domain         string     `json:"domain,omitempty"`
	Nonce          string     `json:"nonce,omitempty"`
}

// FromBytes creates an instance of DIDDocument by reading a JSON document from bytes
func FromBytes(data []byte) (*Doc, error) {
	// validate did document
	if err := validate(data); err != nil {
		return nil, err
	}

	raw := &rawDoc{}
	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, errors.Errorf("Json marshalling of did doc bytes bytes failed: %w", err)
	}

	publicKeys, err := populatePublicKeys(raw.PublicKey)
	if err != nil {
		return nil, errors.Errorf("populate public keys failed: %w", err)
	}
	authPKs, err := populateAuthentications(raw.Authentication, publicKeys)
	if err != nil {
		return nil, errors.Errorf("populate authentications failed: %w", err)
	}

	return &Doc{Context: raw.Context,
		ID:             raw.ID,
		PublicKey:      publicKeys,
		Service:        populateServices(raw.Service),
		Authentication: authPKs,
		Created:        raw.Created,
		Updated:        raw.Updated,
		Proof:          raw.Proof,
	}, nil
}

func populateServices(rawServices []map[string]interface{}) []Service {
	var services []Service
	for _, rawService := range rawServices {
		service := Service{ID: stringEntry(rawService[jsonldID]), Type: stringEntry(rawService[jsonldType]),
			ServiceEndpoint: stringEntry(rawService[jsonldServicePoint])}
		delete(rawService, jsonldID)
		delete(rawService, jsonldType)
		delete(rawService, jsonldServicePoint)
		service.Properties = rawService
		services = append(services, service)
	}
	return services
}

func populateAuthentications(rawAuthentications []interface{}, pks []PublicKey) ([]VerificationMethod, error) {
	var vms []VerificationMethod
	for _, rawAuthentication := range rawAuthentications {
		valueString, ok := rawAuthentication.(string)
		if ok {
			keyExist := false
			for _, pk := range pks {
				if pk.ID == valueString {
					vms = append(vms, VerificationMethod{pk})
					keyExist = true
					break
				}
			}
			if !keyExist {
				return nil, errors.Errorf("authentication key %s not exist in did doc public key", valueString)
			}
			continue
		}

		valuePK, ok := rawAuthentication.(map[string]interface{})
		if !ok {
			return nil, errors.New("rawAuthentication is not map[string]interface{}")
		}
		pk, err := populatePublicKeys([]map[string]interface{}{valuePK})
		if err != nil {
			return nil, err
		}
		vms = append(vms, VerificationMethod{pk[0]})

	}
	return vms, nil

}

func populatePublicKeys(rawPKs []map[string]interface{}) ([]PublicKey, error) {
	var publicKeys []PublicKey
	for _, rawPK := range rawPKs {
		decodeValue, err := decodePK(rawPK)
		if err != nil {
			return nil, err
		}
		publicKeys = append(publicKeys, PublicKey{ID: stringEntry(rawPK[jsonldID]), Type: stringEntry(rawPK[jsonldType]),
			Controller: stringEntry(rawPK[jsonldController]), Value: decodeValue})

	}
	return publicKeys, nil
}

func decodePK(rawPK map[string]interface{}) ([]byte, error) {
	if stringEntry(rawPK[jsonldPublicKeyBase58]) != "" {
		return base58.Decode(stringEntry(rawPK[jsonldPublicKeyBase58])), nil
	}
	if stringEntry(rawPK[jsonldPublicKeyHex]) != "" {
		value, err := hex.DecodeString(stringEntry(rawPK[jsonldPublicKeyHex]))
		if err != nil {
			return nil, errors.Errorf("decode public key hex failed: %w", err)
		}
		return value, nil
	}
	if stringEntry(rawPK[jsonldPublicKeyPem]) != "" {
		block, _ := pem.Decode([]byte(stringEntry(rawPK[jsonldPublicKeyPem])))
		if block == nil {
			return nil, errors.New("failed to decode PEM block containing public key")
		}
		return block.Bytes, nil
	}

	return nil, errors.New("public key encoding not supported")

}

func validate(data []byte) error {
	// Validate that the DID Document conforms to the serialization of the DID Document data model (https://w3c-ccg.github.io/did-spec/#did-documents)
	documentLoader := gojsonschema.NewStringLoader(string(data))
	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return errors.Errorf("Validation of did doc failed: %w", err)
	}

	if !result.Valid() {
		errMsg := "did document not valid:\n"
		for _, desc := range result.Errors() {
			errMsg = errMsg + fmt.Sprintf("- %s\n", desc)
		}
		return errors.New(errMsg)
	}
	return nil
}

// stringEntry
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}
	return entry.(string)
}

// JSONBytes converts document to json bytes
func (doc *Doc) JSONBytes() ([]byte, error) {
	raw := &rawDoc{
		Context:        doc.Context,
		ID:             doc.ID,
		PublicKey:      populateRawPublicKeys(doc.PublicKey),
		Authentication: populateRawAuthentications(doc.Authentication),
		Service:        populateRawServices(doc.Service),
		Created:        doc.Created,
		Proof:          doc.Proof,
		Updated:        doc.Updated,
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, errors.Errorf("Json unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

func populateRawServices(services []Service) []map[string]interface{} {
	var rawServices []map[string]interface{}
	for _, service := range services {
		rawService := make(map[string]interface{})

		for k, v := range service.Properties {
			rawService[k] = v
		}

		rawService[jsonldID] = service.ID
		rawService[jsonldType] = service.Type
		rawService[jsonldServicePoint] = service.ServiceEndpoint

		rawServices = append(rawServices, rawService)
	}
	return rawServices
}

func populateRawPublicKeys(pks []PublicKey) []map[string]interface{} {
	var rawPKs []map[string]interface{}
	for _, pk := range pks {
		rawPKs = append(rawPKs, populateRawPublicKey(pk))
	}
	return rawPKs
}

func populateRawPublicKey(pk PublicKey) map[string]interface{} {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID
	rawPK[jsonldType] = pk.Type
	rawPK[jsonldController] = pk.Controller

	if pk.Value != nil {
		rawPK[jsonldPublicKeyBase58] = base58.Encode(pk.Value)
	}

	return rawPK
}

func populateRawAuthentications(vms []VerificationMethod) []interface{} {
	var rawAuthentications []interface{}

	for _, vm := range vms {
		rawAuthentications = append(rawAuthentications, populateRawPublicKey(vm.PublicKey))
	}

	return rawAuthentications
}
