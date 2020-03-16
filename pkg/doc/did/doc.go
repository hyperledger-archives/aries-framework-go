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
	"regexp"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	// Context of the DID document
	Context             = "https://w3id.org/did/v1"
	contextV011         = "https://w3id.org/did/v0.11"
	jsonldType          = "type"
	jsonldID            = "id"
	jsonldPublicKey     = "publicKey"
	jsonldServicePoint  = "serviceEndpoint"
	jsonldRecipientKeys = "recipientKeys"
	jsonldRoutingKeys   = "routingKeys"
	jsonldPriority      = "priority"
	jsonldController    = "controller"
	jsonldOwner         = "owner"

	jsonldCreator        = "creator"
	jsonldCreated        = "created"
	jsonldProofValue     = "proofValue"
	jsonldSignatureValue = "signatureValue"
	jsonldDomain         = "domain"
	jsonldNonce          = "nonce"

	// various public key encodings
	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyHex    = "publicKeyHex"
	jsonldPublicKeyPem    = "publicKeyPem"
	schemaV1              = `{
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

	schemaV011 = `{
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
          "pattern": "^https://w3id.org/did/v0.11$"
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
            "$ref": "#/definitions/publicKeyReferenced"
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
          "type": "string"
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
    },
    "publicKey": {
      "required": [
        "id",
        "type"
      ],
      "type": "object",
      "minProperties": 3,
      "maxProperties": 4,
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "owner": {
          "type": "string"
        }
      }
    },
    "publicKeyReferenced": {
      "required": [
        "type",
        "publicKey"
      ],
      "type": "object",
      "minProperties": 2,
      "maxProperties": 2,
      "properties": {
        "type": {
          "type": "string"
        },
        "publicKey": {
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

var schemaLoaderV1 = gojsonschema.NewStringLoader(schemaV1)     //nolint:gochecknoglobals
var schemaLoaderV011 = gojsonschema.NewStringLoader(schemaV011) //nolint:gochecknoglobals

// DID is parsed according to the generic syntax: https://w3c.github.io/did-core/#generic-did-syntax
type DID struct {
	Scheme           string // Scheme is always "did"
	Method           string // Method is the specific DID methods
	MethodSpecificID string // MethodSpecificID is the unique ID computed or assigned by the DID method
}

// String returns a string representation of this DID
func (d *DID) String() string {
	return fmt.Sprintf("%s:%s:%s", d.Scheme, d.Method, d.MethodSpecificID)
}

// Parse parses the string according to the generic DID syntax.
// See https://w3c.github.io/did-core/#generic-did-syntax.
func Parse(did string) (*DID, error) {
	// I could not find a good ABNF parser :(
	const idchar = `a-zA-Z0-9-_\.`
	regex := fmt.Sprintf(`^did:[a-z0-9]+:(:+|[:%s]+)*[%s]+$`, idchar, idchar)

	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex=%s (this should not have happened!). %w", regex, err)
	}

	if !r.MatchString(did) {
		return nil, fmt.Errorf(
			"invalid did: %s. Make sure it conforms to the generic DID syntax: https://w3c.github.io/did-core/#generic-did-syntax", //nolint:lll
			did)
	}

	parts := strings.SplitN(did, ":", 3)

	return &DID{
		Scheme:           "did",
		Method:           parts[1],
		MethodSpecificID: parts[2],
	}, nil
}

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
	Priority        uint
	RecipientKeys   []string
	RoutingKeys     []string
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
	raw := &rawDoc{}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of did doc bytes bytes failed: %w", err)
	} else if raw == nil {
		return nil, errors.New("document payload is not provided")
	}
	// validate did document
	err = validate(data, raw.schemaLoader())
	if err != nil {
		return nil, err
	}

	publicKeys, err := populatePublicKeys(raw.Context[0], raw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("populate public keys failed: %w", err)
	}

	authPKs, err := populateAuthentications(raw.Context[0], raw.Authentication, publicKeys)
	if err != nil {
		return nil, fmt.Errorf("populate authentications failed: %w", err)
	}

	proofs, err := populateProofs(raw.Context[0], raw.Proof)
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

func populateProofs(context string, rawProofs []interface{}) ([]Proof, error) {
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

		proofKey := jsonldProofValue

		if context == contextV011 {
			proofKey = jsonldSignatureValue
		}

		proofValue, err := base64.RawURLEncoding.DecodeString(stringEntry(emap[proofKey]))
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
		service := Service{ID: stringEntry(rawService[jsonldID]),
			Type:            stringEntry(rawService[jsonldType]),
			ServiceEndpoint: stringEntry(rawService[jsonldServicePoint]),
			RecipientKeys:   stringArray(rawService[jsonldRecipientKeys]),
			RoutingKeys:     stringArray(rawService[jsonldRoutingKeys]),
			Priority:        uintEntry(rawService[jsonldPriority])}

		delete(rawService, jsonldID)
		delete(rawService, jsonldType)
		delete(rawService, jsonldServicePoint)
		delete(rawService, jsonldRecipientKeys)
		delete(rawService, jsonldRoutingKeys)
		delete(rawService, jsonldPriority)

		service.Properties = rawService
		services = append(services, service)
	}

	return services
}

func populateAuthentications(context string, rawAuthentications []interface{},
	pks []PublicKey) ([]VerificationMethod, error) {
	var vms []VerificationMethod

	for _, rawAuthentication := range rawAuthentications {
		keyID, keyIDExist := rawAuthentication.(string)

		if context == contextV011 {
			m, ok := rawAuthentication.(map[string]interface{})
			if !ok {
				return nil, errors.New("rawAuthentication is not map[string]interface{}")
			}

			keyID, keyIDExist = m[jsonldPublicKey].(string)
		}

		if keyIDExist {
			keyExist := false

			for _, pk := range pks {
				if pk.ID == keyID {
					vms = append(vms, VerificationMethod{pk})
					keyExist = true

					break
				}
			}

			if !keyExist {
				return nil, fmt.Errorf("authentication key %s not exist in did doc public key", keyID)
			}

			continue
		}

		valuePK, ok := rawAuthentication.(map[string]interface{})
		if !ok {
			return nil, errors.New("rawAuthentication is not map[string]interface{}")
		}

		pk, err := populatePublicKeys(context, []map[string]interface{}{valuePK})
		if err != nil {
			return nil, err
		}

		vms = append(vms, VerificationMethod{pk[0]})
	}

	return vms, nil
}

func populatePublicKeys(context string, rawPKs []map[string]interface{}) ([]PublicKey, error) {
	var publicKeys []PublicKey

	for _, rawPK := range rawPKs {
		decodeValue, err := decodePK(rawPK)
		if err != nil {
			return nil, err
		}

		controllerKey := jsonldController

		if context == contextV011 {
			controllerKey = jsonldOwner
		}

		publicKeys = append(publicKeys, PublicKey{ID: stringEntry(rawPK[jsonldID]), Type: stringEntry(rawPK[jsonldType]),
			Controller: stringEntry(rawPK[controllerKey]), Value: decodeValue})
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

func (r *rawDoc) schemaLoader() gojsonschema.JSONLoader {
	schemaLoader := schemaLoaderV1
	if len(r.Context) > 0 && r.Context[0] == contextV011 {
		schemaLoader = schemaLoaderV011
	}

	return schemaLoader
}

func validate(data []byte, schemaLoader gojsonschema.JSONLoader) error {
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

// uintEntry
func uintEntry(entry interface{}) uint {
	if entry == nil {
		return 0
	}

	return uint(entry.(float64))
}

// stringArray
func stringArray(entry interface{}) []string {
	if entry == nil {
		return nil
	}

	entries, ok := entry.([]interface{})
	if !ok {
		return nil
	}

	var result []string

	for _, e := range entries {
		if e != nil {
			result = append(result, stringEntry(e))
		}
	}

	return result
}

// JSONBytes converts document to json bytes
func (doc *Doc) JSONBytes() ([]byte, error) {
	context := Context

	if len(doc.Context) > 0 {
		context = doc.Context[0]
	}

	raw := &rawDoc{
		Context:        doc.Context,
		ID:             doc.ID,
		PublicKey:      populateRawPublicKeys(context, doc.PublicKey),
		Authentication: populateRawAuthentications(context, doc.Authentication),
		Service:        populateRawServices(doc.Service),
		Created:        doc.Created,
		Proof:          populateRawProofs(context, doc.Proof),
		Updated:        doc.Updated,
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

// signatureSuite encapsulates signature suite methods required for signature verification
type signatureSuite interface {

	// GetCanonicalDocument will return normalized/canonical version of the document
	GetCanonicalDocument(doc map[string]interface{}) ([]byte, error)

	// GetDigest returns document digest
	GetDigest(doc []byte) []byte

	// Verify will verify signature against public key
	Verify(pubKey *verifier.PublicKey, doc []byte, signature []byte) error

	// Accept registers this signature suite with the given signature type
	Accept(signatureType string) bool
}

// VerifyProof verifies document proofs
func (doc *Doc) VerifyProof(suite signatureSuite) error {
	if len(doc.Proof) == 0 {
		return ErrProofNotFound
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		return err
	}

	v := verifier.New(&didKeyResolver{doc.PublicKey}, suite)

	return v.Verify(docBytes)
}

// ErrProofNotFound is returned when proof is not found
var ErrProofNotFound = errors.New("proof not found")

// didKeyResolver implements public key resolution for DID public keys
type didKeyResolver struct {
	PubKeys []PublicKey
}

func (r *didKeyResolver) Resolve(id string) (*verifier.PublicKey, error) {
	for _, key := range r.PubKeys {
		if key.ID == id {
			return &verifier.PublicKey{
				Type:  kms.KeyType(key.Type),
				Value: key.Value,
			}, nil
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
		rawService[jsonldRecipientKeys] = service.RecipientKeys
		rawService[jsonldRoutingKeys] = service.RoutingKeys
		rawService[jsonldPriority] = service.Priority

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}

func populateRawPublicKeys(context string, pks []PublicKey) []map[string]interface{} {
	var rawPKs []map[string]interface{}
	for _, pk := range pks {
		rawPKs = append(rawPKs, populateRawPublicKey(context, pk))
	}

	return rawPKs
}

func populateRawPublicKey(context string, pk PublicKey) map[string]interface{} {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID
	rawPK[jsonldType] = pk.Type

	if context == contextV011 {
		rawPK[jsonldOwner] = pk.Controller
	} else {
		rawPK[jsonldController] = pk.Controller
	}

	if pk.Value != nil {
		rawPK[jsonldPublicKeyBase58] = base58.Encode(pk.Value)
	}

	return rawPK
}

func populateRawAuthentications(context string, vms []VerificationMethod) []interface{} {
	var rawAuthentications []interface{}

	for _, vm := range vms {
		rawAuthentications = append(rawAuthentications, populateRawPublicKey(context, vm.PublicKey))
	}

	return rawAuthentications
}

func populateRawProofs(context string, proofs []Proof) []interface{} {
	rawProofs := make([]interface{}, 0, len(proofs))

	k := jsonldProofValue

	if context == contextV011 {
		k = jsonldSignatureValue
	}

	for _, p := range proofs {
		rawProofs = append(rawProofs, map[string]interface{}{
			jsonldType:    p.Type,
			jsonldCreated: p.Created,
			jsonldCreator: p.Creator,
			k:             base64.RawURLEncoding.EncodeToString(p.ProofValue),
			jsonldDomain:  p.Domain,
			jsonldNonce:   base64.RawURLEncoding.EncodeToString(p.Nonce),
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
