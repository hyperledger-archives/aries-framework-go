/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const (
	// Context of the DID document
	Context            = "https://w3id.org/did/v1"
	jsonldType         = "type"
	jsonldID           = "id"
	jsonldServicePoint = "serviceEndpoint"
	jsonldController   = "controller"

	jsonldCreator    = "creator"
	jsonldCreated    = "created"
	jsonldProofValue = "proofValue"
	jsonldDomain     = "domain"
	jsonldNonce      = "nonce"

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
      "type": "string"
    },
    "updated": {
      "type": "string"
    },
    "proof": {
      "type": "array",
      "items": {
        "$ref": "#/definitions/proof"
      }
    }
  },
  "definitions": {
	"proof": {
      "type": "object",
      "required": [ "type", "creator", "created", "proofValue"],
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
          "type": "string"
        },
        "proofValue": {
          "type": "string"
        },
        "domain": {
          "type": "string"
        },
        "nonce": {
          "type": "string"
        }
	  }
    },
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

var schemaLoader = gojsonschema.NewStringLoader(schema) //nolint:gochecknoglobals

// Doc DID Document definition
type Doc struct {
	Context        []string
	ID             string
	PublicKey      []PublicKey
	Service        []Service
	Authentication []VerificationMethod
	Created        *time.Time
	Updated        *time.Time
	Proof          []Proof
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
	Proof          []interface{}            `json:"proof,omitempty"`
}

// Proof is cryptographic proof of the integrity of the DID Document
type Proof struct {
	Type       string
	Created    *time.Time
	Creator    string
	ProofValue []byte
	Domain     string
	Nonce      []byte
}

// ParseDocument creates an instance of DIDDocument by reading a JSON document from bytes
func ParseDocument(data []byte) (*Doc, error) {
	// validate did document
	if err := validate(data); err != nil {
		return nil, err
	}

	raw := &rawDoc{}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of did doc bytes bytes failed: %w", err)
	}

	publicKeys, err := populatePublicKeys(raw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("populate public keys failed: %w", err)
	}

	authPKs, err := populateAuthentications(raw.Authentication, publicKeys)
	if err != nil {
		return nil, fmt.Errorf("populate authentications failed: %w", err)
	}

	proofs, err := populateProofs(raw.Proof)
	if err != nil {
		return nil, fmt.Errorf("populate proofs failed: %w", err)
	}

	return &Doc{Context: raw.Context,
		ID:             raw.ID,
		PublicKey:      publicKeys,
		Service:        populateServices(raw.Service),
		Authentication: authPKs,
		Created:        raw.Created,
		Updated:        raw.Updated,
		Proof:          proofs,
	}, nil
}

func populateProofs(rawProofs []interface{}) ([]Proof, error) {
	proofs := make([]Proof, 0, len(rawProofs))

	for _, rawProof := range rawProofs {
		emap, ok := rawProof.(map[string]interface{})
		if !ok {
			return nil, errors.New("rawProofs is not map[string]interface{}")
		}

		created := stringEntry(emap[jsonldCreated])

		timeValue, err := time.Parse(time.RFC3339, created)
		if err != nil {
			return nil, err
		}

		proofValue, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldProofValue]))
		if err != nil {
			return nil, err
		}

		nonce, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[jsonldNonce]))
		if err != nil {
			return nil, err
		}

		proof := Proof{
			Type:       stringEntry(emap[jsonldType]),
			Created:    &timeValue,
			Creator:    stringEntry(emap[jsonldCreator]),
			ProofValue: proofValue,
			Domain:     stringEntry(emap[jsonldDomain]),
			Nonce:      nonce,
		}

		proofs = append(proofs, proof)
	}

	return proofs, nil
}

func populateServices(rawServices []map[string]interface{}) []Service {
	services := make([]Service, 0, len(rawServices))

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
				return nil, fmt.Errorf("authentication key %s not exist in did doc public key", valueString)
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
			return nil, fmt.Errorf("decode public key hex failed: %w", err)
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
	// Validate that the DID Document conforms to the serialization of the DID Document data model.
	// Reference: https://w3c-ccg.github.io/did-spec/#did-documents)
	documentLoader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(schemaLoader, documentLoader)
	if err != nil {
		return fmt.Errorf("validation of DID doc failed: %w", err)
	}

	if !result.Valid() {
		errMsg := "did document not valid:\n"
		for _, desc := range result.Errors() {
			errMsg += fmt.Sprintf("- %s\n", desc)
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
		Proof:          populateRawProofs(doc.Proof),
		Updated:        doc.Updated,
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

// VerifyProof verifies document proofs
func (doc *Doc) VerifyProof() error {
	if len(doc.Proof) == 0 {
		return ErrProofNotFound
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		return err
	}

	v := verifier.New(&didKeyResolver{doc.PublicKey})

	return v.Verify(docBytes)
}

// ErrProofNotFound is returned when proof is not found
var ErrProofNotFound = errors.New("proof not found")

// didKeyResolver implements public key resolution for DID public keys
type didKeyResolver struct {
	PubKeys []PublicKey
}

func (r *didKeyResolver) Resolve(id string) ([]byte, error) {
	for _, key := range r.PubKeys {
		if key.ID == id {
			return key.Value, nil
		}
	}

	return nil, ErrKeyNotFound
}

// ErrKeyNotFound is returned when key is not found
var ErrKeyNotFound = errors.New("key not found")

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

func populateRawProofs(proofs []Proof) []interface{} {
	rawProofs := make([]interface{}, 0, len(proofs))
	for _, p := range proofs {
		rawProofs = append(rawProofs, map[string]interface{}{
			jsonldType:       p.Type,
			jsonldCreated:    p.Created,
			jsonldCreator:    p.Creator,
			jsonldProofValue: base64.RawURLEncoding.EncodeToString(p.ProofValue),
			jsonldDomain:     p.Domain,
			jsonldNonce:      base64.RawURLEncoding.EncodeToString(p.Nonce),
		})
	}

	return rawProofs
}

// DocOption provides options to build DID Doc.
type DocOption func(opts *Doc)

// WithPublicKey DID doc PublicKey.
func WithPublicKey(pubKey []PublicKey) DocOption {
	return func(opts *Doc) {
		opts.PublicKey = pubKey
	}
}

// WithAuthentication DID doc Authentication.
func WithAuthentication(auth []VerificationMethod) DocOption {
	return func(opts *Doc) {
		opts.Authentication = auth
	}
}

// WithService DID doc services.
func WithService(svc []Service) DocOption {
	return func(opts *Doc) {
		opts.Service = svc
	}
}

// WithCreatedTime DID doc created time.
func WithCreatedTime(t time.Time) DocOption {
	return func(opts *Doc) {
		opts.Created = &t
	}
}

// WithUpdatedTime DID doc updated time.
func WithUpdatedTime(t time.Time) DocOption {
	return func(opts *Doc) {
		opts.Updated = &t
	}
}

// BuildDoc creates the DID Doc from options.
func BuildDoc(opts ...DocOption) *Doc {
	doc := &Doc{}
	doc.Context = []string{Context}

	for _, opt := range opts {
		opt(doc)
	}

	return doc
}
