/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

//go:generate testdata/scripts/openssl_env.sh testdata/scripts/generate_test_keys.sh

var logger = log.New("aries-framework/doc/verifiable")

const defaultSchema = `{
  "required": [
    "@context",
    "type",
    "credentialSubject",
    "issuer",
    "issuanceDate"
  ],
  "properties": {
    "@context": {
      "oneOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/2018/credentials/v1"
        },
        {
          "type": "array",
          "items": [
            {
              "type": "string",
              "const": "https://www.w3.org/2018/credentials/v1"
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
        }
      ]
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
              "pattern": "^VerifiableCredential$"
            }
          ]
        },
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
        },
        {
          "type": "string"
        }
      ]
    },
    "issuer": {
      "anyOf": [
        {
          "type": "string",
          "format": "uri"
        },
        {
          "type": "object",
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "type": "string",
              "format": "uri"
            }
          }
        }
      ]
    },
    "issuanceDate": {
      "type": "string",
      "format": "date-time"
    },
    "proof": {
      "anyOf": [
        {
          "$ref": "#/definitions/proof"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/proof"
          }
        },        
        {
          "type": "null"
        }
      ]
    },
    "expirationDate": {
      "type": [
        "string",
        "null"
      ],
      "format": "date-time"
    },
    "credentialStatus": {
      "$ref": "#/definitions/typedID"
    },
    "credentialSchema": {
      "$ref": "#/definitions/typedIDs"
    },
    "evidence": {
      "$ref": "#/definitions/typedIDs"
    },
    "refreshService": {
      "$ref": "#/definitions/typedID"
    }
  },
  "definitions": {
    "typedID": {
      "anyOf": [
        {
          "type": "null"
        },
        {
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
        }
      ]
    },
    "typedIDs": {
      "anyOf": [
        {
          "$ref": "#/definitions/typedID"
        },
        {
          "type": "array",
          "items": {
            "$ref": "#/definitions/typedID"
          }
        },
        {
          "type": "null"
        }
      ]
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

// https://www.w3.org/TR/vc-data-model/#data-schemas
const jsonSchema2018Type = "JsonSchemaValidator2018"

const (
	// https://www.w3.org/TR/vc-data-model/#base-context
	baseContext = "https://www.w3.org/2018/credentials/v1"

	// https://www.w3.org/TR/vc-data-model/#types
	vcType = "VerifiableCredential"

	// https://www.w3.org/TR/vc-data-model/#presentations-0
	vpType = "VerifiablePresentation"
)

// vcModelValidationMode defines constraint put on context and type of VC.
type vcModelValidationMode int

const (
	// combinedValidation when set it makes JSON validation using JSON Schema and JSON-LD validation.
	//
	// JSON validation verifies the format of the fields and the presence of
	// mandatory fields. It can also decline VC with field(s) not defined in the schema if
	// additionalProperties=true is configured in that schema. To enable such check for base JSON schema, use
	// WithStrictValidation() option.
	//
	// JSON-LD validation is applied when there is more than one (base) context defined. In this case,
	// JSON-LD parser can load machine-readable vocabularies used to describe information in the data model.
	// In JSON-LD schemas, it's not possible to define custom mandatory fields. A possibility to decline
	// JSON document with field(s) not defined in any of JSON-LD schema is built on top of JSON-LD parser and is
	// enabled using WithStrictValidation().
	//
	// This is a default validation mode.
	combinedValidation vcModelValidationMode = iota

	// jsonldValidation when set it uses JSON-LD parser for validation.
	jsonldValidation

	// baseContextValidation when defined it's validated that only the fields and values (when applicable)
	// are present in the document. No extra fields are allowed (outside of credentialSubject).
	baseContextValidation

	// baseContextExtendedValidation when set it's validated that fields that are specified in base context are
	// as specified. Additional fields are allowed.
	baseContextExtendedValidation
)

// SchemaCache defines a cache of credential schemas.
type SchemaCache interface {

	// Put element to the cache.
	Put(k string, v []byte)

	// Get element from the cache, returns false at second return value if element is not present.
	Get(k string) ([]byte, bool)
}

// cache defines a cache interface
type cache interface {
	Set(k, v []byte)

	HasGet(dst, k []byte) ([]byte, bool)

	Del(k []byte)
}

// ExpirableSchemaCache is an implementation of SchemaCache based fastcache.Cache with expirable elements.
type ExpirableSchemaCache struct {
	cache      cache
	expiration time.Duration
}

// CredentialSchemaLoader defines expirable cache.
type CredentialSchemaLoader struct {
	schemaDownloadClient *http.Client
	cache                SchemaCache
	jsonLoader           gojsonschema.JSONLoader
}

// CredentialSchemaLoaderBuilder defines a builder of CredentialSchemaLoader.
type CredentialSchemaLoaderBuilder struct {
	loader *CredentialSchemaLoader
}

// NewCredentialSchemaLoaderBuilder creates a new instance of CredentialSchemaLoaderBuilder.
func NewCredentialSchemaLoaderBuilder() *CredentialSchemaLoaderBuilder {
	return &CredentialSchemaLoaderBuilder{
		loader: &CredentialSchemaLoader{},
	}
}

// SetSchemaDownloadClient sets HTTP client to be used to download the schema.
func (b *CredentialSchemaLoaderBuilder) SetSchemaDownloadClient(client *http.Client) *CredentialSchemaLoaderBuilder {
	b.loader.schemaDownloadClient = client
	return b
}

// SetCache defines SchemaCache.
func (b *CredentialSchemaLoaderBuilder) SetCache(cache SchemaCache) *CredentialSchemaLoaderBuilder {
	b.loader.cache = cache
	return b
}

// SetJSONLoader defines gojsonschema.JSONLoader
func (b *CredentialSchemaLoaderBuilder) SetJSONLoader(loader gojsonschema.JSONLoader) *CredentialSchemaLoaderBuilder {
	b.loader.jsonLoader = loader
	return b
}

// Build constructed CredentialSchemaLoader.
// It creates default HTTP client and JSON schema loader if not defined.
func (b *CredentialSchemaLoaderBuilder) Build() *CredentialSchemaLoader {
	l := b.loader

	if l.schemaDownloadClient == nil {
		l.schemaDownloadClient = &http.Client{}
	}

	if l.jsonLoader == nil {
		l.jsonLoader = defaultSchemaLoader()
	}

	return l
}

// Put element to the cache. It also adds a mark of when the element will expire.
func (sc *ExpirableSchemaCache) Put(k string, v []byte) {
	expires := time.Now().Add(sc.expiration).Unix()

	const numBytesTime = 8

	b := make([]byte, numBytesTime)
	binary.LittleEndian.PutUint64(b, uint64(expires))

	ve := make([]byte, numBytesTime+len(v))
	copy(ve[:numBytesTime], b)
	copy(ve[numBytesTime:], v)

	sc.cache.Set([]byte(k), ve)
}

// Get element from the cache. If element is present, it checks if the element is expired.
// If yes, it clears the element from the cache and indicates that the key is not found.
func (sc *ExpirableSchemaCache) Get(k string) ([]byte, bool) {
	b, ok := sc.cache.HasGet(nil, []byte(k))
	if !ok {
		return nil, false
	}

	const numBytesTime = 8

	expires := int64(binary.LittleEndian.Uint64(b[:numBytesTime]))
	if expires < time.Now().Unix() {
		// cache expires
		sc.cache.Del([]byte(k))
		return nil, false
	}

	return b[numBytesTime:], true
}

// Evidence defines evidence of Verifiable Credential
type Evidence interface{}

// Issuer of the Verifiable Credential
type Issuer struct {
	ID string `json:"id,omitempty"`

	CustomFields CustomFields `json:"-"`
}

// MarshalJSON marshals Issuer to JSON.
func (i Issuer) MarshalJSON() ([]byte, error) {
	if len(i.CustomFields) == 0 {
		// as string
		return json.Marshal(i.ID)
	}

	// as object
	type Alias Issuer

	alias := Alias(i)

	data, err := marshalWithCustomFields(alias, i.CustomFields)
	if err != nil {
		return nil, fmt.Errorf("marshal Issuer: %w", err)
	}

	return data, nil
}

// UnmarshalJSON unmarshals issuer from JSON.
func (i *Issuer) UnmarshalJSON(bytes []byte) error {
	var issuerID string

	if err := json.Unmarshal(bytes, &issuerID); err == nil {
		// as string
		i.ID = issuerID
		return nil
	}

	// as object
	type Alias Issuer

	alias := (*Alias)(i)

	i.CustomFields = make(CustomFields)

	err := unmarshalWithCustomFields(bytes, alias, i.CustomFields)
	if err != nil {
		return fmt.Errorf("unmarshal Issuer: %w", err)
	}

	if i.ID == "" {
		return errors.New("issuer ID is not defined")
	}

	return nil
}

// Subject of the Verifiable Credential
type Subject interface{}

// Credential Verifiable Credential definition
type Credential struct {
	Context        []string
	CustomContext  []interface{}
	ID             string
	Types          []string
	Subject        Subject
	Issuer         Issuer
	Issued         *time.Time
	Expired        *time.Time
	Proofs         []Proof
	Status         *TypedID
	Schemas        []TypedID
	Evidence       Evidence
	TermsOfUse     []TypedID
	RefreshService []TypedID

	CustomFields CustomFields
	rawFields    rememberedFields
}

// rawCredential is a basic verifiable credential
type rawCredential struct {
	Context        interface{}     `json:"@context,omitempty"`
	ID             string          `json:"id,omitempty"`
	Type           interface{}     `json:"type,omitempty"`
	Subject        Subject         `json:"credentialSubject,omitempty"`
	Issued         interface{}     `json:"issuanceDate,omitempty"`
	Expired        interface{}     `json:"expirationDate,omitempty"`
	Proof          json.RawMessage `json:"proof,omitempty"`
	Status         *TypedID        `json:"credentialStatus,omitempty"`
	Issuer         json.RawMessage `json:"issuer,omitempty"`
	Schema         interface{}     `json:"credentialSchema,omitempty"`
	Evidence       Evidence        `json:"evidence,omitempty"`
	TermsOfUse     json.RawMessage `json:"termsOfUse,omitempty"`
	RefreshService json.RawMessage `json:"refreshService,omitempty"`

	// All unmapped fields are put here.
	CustomFields `json:"-"`
}

// MarshalJSON defines custom marshalling of rawCredential to JSON.
func (rc *rawCredential) MarshalJSON() ([]byte, error) {
	type Alias rawCredential

	alias := (*Alias)(rc)

	return marshalWithCustomFields(alias, rc.CustomFields)
}

// UnmarshalJSON defines custom unmarshalling of rawCredential from JSON.
func (rc *rawCredential) UnmarshalJSON(data []byte) error {
	type Alias rawCredential

	alias := (*Alias)(rc)
	rc.CustomFields = make(CustomFields)

	err := unmarshalWithCustomFields(data, alias, rc.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder func(dataJSON []byte, vc *Credential) error

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate func() *Credential

// credentialOpts holds options for the Verifiable Credential decoding
type credentialOpts struct {
	publicKeyFetcher      PublicKeyFetcher
	disabledCustomSchema  bool
	schemaLoader          *CredentialSchemaLoader
	modelValidationMode   vcModelValidationMode
	allowedCustomContexts map[string]bool
	allowedCustomTypes    map[string]bool
	disabledProofCheck    bool
	strictValidation      bool
	ldpSuites             []verifier.SignatureSuite

	jsonldCredentialOpts
}

// CredentialOpt is the Verifiable Credential decoding option
type CredentialOpt func(opts *credentialOpts)

// WithDisabledProofCheck option for disabling of proof check.
func WithDisabledProofCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledProofCheck = true
	}
}

// WithNoCustomSchemaCheck option is for disabling of Credential Schemas download if defined
// in Verifiable Credential. Instead, the Verifiable Credential is checked against default Schema.
func WithNoCustomSchemaCheck() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.disabledCustomSchema = true
	}
}

// WithPublicKeyFetcher set public key fetcher used when decoding from JWS.
func WithPublicKeyFetcher(fetcher PublicKeyFetcher) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.publicKeyFetcher = fetcher
	}
}

// WithCredentialSchemaLoader option is used to define custom credentials schema loader.
// If not defined, the default one is created with default HTTP client to download the schema
// and no caching of the schemas.
func WithCredentialSchemaLoader(loader *CredentialSchemaLoader) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.schemaLoader = loader
	}
}

// WithJSONLDValidation uses the JSON LD parser for validation.
func WithJSONLDValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = jsonldValidation
	}
}

// WithBaseContextValidation validates that only the fields and values (when applicable) are present
// in the document. No extra fields are allowed (outside of credentialSubject).
func WithBaseContextValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = baseContextValidation
	}
}

// WithBaseContextExtendedValidation validates that fields that are specified in base context are as specified.
// Additional fields are allowed
func WithBaseContextExtendedValidation(customContexts, customTypes []string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.modelValidationMode = baseContextExtendedValidation

		opts.allowedCustomContexts = make(map[string]bool)
		for _, context := range customContexts {
			opts.allowedCustomContexts[context] = true
		}

		opts.allowedCustomContexts[baseContext] = true

		opts.allowedCustomTypes = make(map[string]bool)
		for _, context := range customTypes {
			opts.allowedCustomTypes[context] = true
		}

		opts.allowedCustomTypes[vcType] = true
	}
}

// WithJSONLDDocumentLoader defines custom JSON-LD document loader. If not defined, when decoding VC
// a new document loader will be created using CachingJSONLDLoader() if JSON-LD validation is made.
func WithJSONLDDocumentLoader(documentLoader ld.DocumentLoader) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithStrictValidation enabled strict validation of VC.
//
// In case of JSON Schema validation, additionalProperties=true is set on the schema.
//
// In case of JSON-LD validation, the comparison of JSON-LD VC document after compaction with original VC one is made.
// In case of mismatch a validation exception is raised.
func WithStrictValidation() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.strictValidation = true
	}
}

// WithExternalJSONLDContext defines external JSON-LD contexts to be used in JSON-LD validation and
// Linked Data Signatures verification.
func WithExternalJSONLDContext(context ...string) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.externalContext = context
	}
}

// WithJSONLDOnlyValidRDF indicates the need to remove all invalid RDF dataset from normalize document
// when verifying linked data signatures of verifiable credential.
func WithJSONLDOnlyValidRDF() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jsonldOnlyValidRDF = true
	}
}

// WithEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VC.
func WithEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.ldpSuites = suites
	}
}

// decodeIssuer decodes raw issuer.
//
// Issuer can be defined by:
//
// - a string which is ID of the issuer;
//
// - object with mandatory "id" field and optional "name" field.
func decodeIssuer(issuerBytes json.RawMessage) (Issuer, error) {
	var issuer Issuer

	err := json.Unmarshal(issuerBytes, &issuer)
	if err != nil {
		return Issuer{}, err
	}

	return issuer, err
}

// decodeCredentialSchemas decodes credential schema(s).
//
// credential schema can be defined as a single object or array of objects.
func decodeCredentialSchemas(data *rawCredential) ([]TypedID, error) {
	switch schema := data.Schema.(type) {
	case []interface{}:
		tids := make([]TypedID, len(schema))

		for i := range schema {
			tid, err := newTypedID(schema[i])
			if err != nil {
				return nil, err
			}

			tids[i] = tid
		}

		return tids, nil

	case interface{}:
		tid, err := newTypedID(schema)
		if err != nil {
			return nil, err
		}

		return []TypedID{tid}, nil

	default:
		return nil, errors.New("verifiable credential schema of unsupported format")
	}
}

// NewCredential decodes Verifiable Credential from bytes which could be marshalled JSON or serialized JWT.
// It also applies miscellaneous options like settings of schema validation.
// It returns decoded Credential and its marshalled JSON.
// For JSON bytes input, the output marshalled JSON is the same value.
// For serialized JWT input, the output is the result of decoding `vc` claim from JWT.
// The output Credential and marshalled JSON can be used for extensions of the base data model
// by checking CustomFields of Credential and/or unmarshalling the JSON to custom date structure.
func NewCredential(vcData []byte, opts ...CredentialOpt) (*Credential, []byte, error) {
	// Apply options.
	vcOpts := parseCredentialOpts(opts)

	// Decode credential (e.g. from JWT).
	vcDataDecoded, err := decodeRaw(vcData, vcOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("decode new credential: %w", err)
	}

	// Unmarshal raw credential from JSON.
	var raw rawCredential
	err = json.Unmarshal(vcDataDecoded, &raw)

	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal new credential: %w", err)
	}

	// Create credential from raw.
	vc, err := newCredential(&raw)
	if err != nil {
		return nil, nil, fmt.Errorf("build new credential: %w", err)
	}

	err = validateCredential(vc, vcDataDecoded, vcOpts)
	if err != nil {
		return nil, nil, err
	}

	return vc, vcDataDecoded, nil
}

// NewUnverifiedCredential decodes Verifiable Credential from bytes which could be marshalled JSON or serialized JWT.
// It does not make a proof check though. Can be used for purposes of decoding of VC stored in a wallet.
// Please use this function with caution.
func NewUnverifiedCredential(vcBytes []byte) (*Credential, error) {
	vcDataDecoded, err := decodeRaw(vcBytes, &credentialOpts{
		disabledProofCheck: true,
	})
	if err != nil {
		return nil, fmt.Errorf("decode new credential: %w", err)
	}

	// Unmarshal raw credential from JSON.
	var raw rawCredential

	err = json.Unmarshal(vcDataDecoded, &raw)
	if err != nil {
		return nil, fmt.Errorf("unmarshal new credential: %w", err)
	}

	// Create credential from raw.
	vc, err := newCredential(&raw)
	if err != nil {
		return nil, fmt.Errorf("build new credential: %w", err)
	}

	return vc, nil
}

func validateCredential(vc *Credential, vcBytes []byte, vcOpts *credentialOpts) error {
	// Credential and type constraint.
	switch vcOpts.modelValidationMode {
	case combinedValidation:
		// TODO Validation mechanism will be changed after completing of #968 and #976
		// Validate VC using JSON schema. Even in case of VC data model extension (i.e. more than one @context
		// is defined and thus JSON-LD validation is made), it's reasonable to do JSON Schema validation
		// prior to the JSON-LD one as the former does not check several aspects like mandatory fields or fields format.
		err := vc.validateJSONSchema(vcBytes, vcOpts)
		if err != nil {
			return err
		}

		return vc.validateJSONLD(vcBytes, vcOpts)

	case jsonldValidation:
		return vc.validateJSONLD(vcBytes, vcOpts)

	case baseContextValidation:
		return validateBaseContext(vc, vcBytes, vcOpts)

	case baseContextExtendedValidation:
		return validateBaseContextWithExtendedValidation(vc, vcOpts, vcBytes)

	default:
		return fmt.Errorf("unsupported vcModelValidationMode: %v", vcOpts.modelValidationMode)
	}
}

func validateBaseContext(vc *Credential, vcBytes []byte, vcOpts *credentialOpts) error {
	if len(vc.Types) > 1 || vc.Types[0] != vcType {
		return errors.New("violated type constraint: not base only type defined")
	}

	if len(vc.Context) > 1 || vc.Context[0] != baseContext {
		return errors.New("violated @context constraint: not base only @context defined")
	}

	return vc.validateJSONSchema(vcBytes, vcOpts)
}

func validateBaseContextWithExtendedValidation(vc *Credential, vcOpts *credentialOpts, vcBytes []byte) error {
	for _, vcContext := range vc.Context {
		if _, ok := vcOpts.allowedCustomContexts[vcContext]; !ok {
			return fmt.Errorf("not allowed @context: %s", vcContext)
		}
	}

	for _, vcType := range vc.Types {
		if _, ok := vcOpts.allowedCustomTypes[vcType]; !ok {
			return fmt.Errorf("not allowed type: %s", vcType)
		}
	}

	return vc.validateJSONSchema(vcBytes, vcOpts)
}

func (vc *Credential) validateJSONLD(vcBytes []byte, vcOpts *credentialOpts) error {
	return compactJSONLD(string(vcBytes), &vcOpts.jsonldCredentialOpts, vcOpts.strictValidation)
}

// CustomCredentialProducer is a factory for Credentials with extended data model.
type CustomCredentialProducer interface {
	// Accept checks if producer is capable of building extended Credential data model.
	Accept(vc *Credential) bool

	// Apply creates custom credential using base credential and its JSON bytes.
	Apply(vc *Credential, dataJSON []byte) (interface{}, error)
}

// CreateCustomCredential creates custom extended credentials from bytes which could be marshalled JSON
// or serialized JWT. It decodes input bytes to the base Verifiable Credential using NewCredential().
// It then checks all producers to find the appropriate which is capable of building extended Credential data model.
// If none of producers accept the credential, the base credential is returned.
func CreateCustomCredential(
	vcData []byte,
	producers []CustomCredentialProducer,
	opts ...CredentialOpt) (interface{}, error) {
	vcBase, vcBytes, credErr := NewCredential(vcData, opts...)
	if credErr != nil {
		return nil, fmt.Errorf("build base verifiable credential: %w", credErr)
	}

	for _, p := range producers {
		if p.Accept(vcBase) {
			customCred, err := p.Apply(vcBase, vcBytes)
			if err != nil {
				return nil, fmt.Errorf("build extended verifiable credential: %w", err)
			}

			return customCred, nil
		}
	}

	// Return base credential as no producers are capable of VC extension.
	return vcBase, nil
}

//nolint: gocyclo,funlen
func newCredential(raw *rawCredential) (*Credential, error) {
	var schemas []TypedID

	if raw.Schema != nil {
		var err error

		schemas, err = decodeCredentialSchemas(raw)
		if err != nil {
			return nil, fmt.Errorf("fill credential schemas from raw: %w", err)
		}
	} else {
		schemas = make([]TypedID, 0)
	}

	types, err := decodeType(raw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill credential types from raw: %w", err)
	}

	issuer, err := decodeIssuer(raw.Issuer)
	if err != nil {
		return nil, fmt.Errorf("fill credential issuer from raw: %w", err)
	}

	context, customContext, err := decodeContext(raw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill credential context from raw: %w", err)
	}

	termsOfUse, err := decodeTypedID(raw.TermsOfUse)
	if err != nil {
		return nil, fmt.Errorf("fill credential terms of use from raw: %w", err)
	}

	refreshService, err := decodeTypedID(raw.RefreshService)
	if err != nil {
		return nil, fmt.Errorf("fill credential refresh service from raw: %w", err)
	}

	proofs, err := decodeProof(raw.Proof)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	issuedDate, err := decodeDate(raw.Issued)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued date from raw: %w", err)
	}

	expiredDate, err := decodeDate(raw.Expired)
	if err != nil {
		return nil, fmt.Errorf("failed to parse issued date from raw: %w", err)
	}

	return &Credential{
		Context:        context,
		CustomContext:  customContext,
		ID:             raw.ID,
		Types:          types,
		Subject:        raw.Subject,
		Issuer:         issuer,
		Issued:         issuedDate,
		Expired:        expiredDate,
		Proofs:         proofs,
		Status:         raw.Status,
		Schemas:        schemas,
		Evidence:       raw.Evidence,
		TermsOfUse:     termsOfUse,
		RefreshService: refreshService,
		CustomFields:   raw.CustomFields,
		rawFields:      preserveRawFields(raw),
	}, nil
}

func preserveRawFields(raw *rawCredential) rememberedFields {
	r := make(rememberedFields)

	r.PushIssuanceDate(raw.Issued)
	r.PushExpirationDate(raw.Expired)

	return r
}

// decodeDate decodes given date to '*time.Time'
// returns nil with no error if nil argument passed
func decodeDate(dateStr interface{}) (*time.Time, error) {
	if dateStr == nil {
		return nil, nil
	}

	d, err := time.Parse(time.RFC3339, dateStr.(string))
	if err != nil {
		return nil, err
	}

	return &d, nil
}

func decodeTypedID(bytes json.RawMessage) ([]TypedID, error) {
	if len(bytes) == 0 {
		return nil, nil
	}

	var singleTypedID TypedID

	err := json.Unmarshal(bytes, &singleTypedID)
	if err == nil {
		return []TypedID{singleTypedID}, nil
	}

	var composedTypedID []TypedID

	err = json.Unmarshal(bytes, &composedTypedID)
	if err == nil {
		return composedTypedID, nil
	}

	return nil, err
}

func decodeRaw(vcData []byte, vcOpts *credentialOpts) ([]byte, error) {
	vcStr := string(vcData)

	if jwt.IsJWS(vcStr) { // External proof, is checked by JWS.
		if vcOpts.publicKeyFetcher == nil && !vcOpts.disabledProofCheck {
			return nil, errors.New("public key fetcher is not defined")
		}

		vcDecodedBytes, err := decodeCredJWS(vcStr, !vcOpts.disabledProofCheck, vcOpts.publicKeyFetcher)
		if err != nil {
			return nil, fmt.Errorf("JWS decoding: %w", err)
		}

		return vcDecodedBytes, nil
	}

	if jwt.IsJWTUnsecured(vcStr) { // Embedded proof.
		vcDecodedBytes, err := decodeCredJWTUnsecured(vcStr)
		if err != nil {
			return nil, fmt.Errorf("unsecured JWT decoding: %w", err)
		}

		return checkEmbeddedProof(vcDecodedBytes, vcOpts)
	}

	// Embedded proof.
	return checkEmbeddedProof(vcData, vcOpts)
}

func parseCredentialOpts(opts []CredentialOpt) *credentialOpts {
	crOpts := &credentialOpts{
		modelValidationMode: combinedValidation,
	}

	for _, opt := range opts {
		opt(crOpts)
	}

	if crOpts.schemaLoader == nil {
		crOpts.schemaLoader = newDefaultSchemaLoader()
	}

	if crOpts.jsonldDocumentLoader == nil {
		crOpts.jsonldDocumentLoader = CachingJSONLDLoader()
	}

	return crOpts
}

func newDefaultSchemaLoader() *CredentialSchemaLoader {
	return &CredentialSchemaLoader{
		schemaDownloadClient: &http.Client{},
		jsonLoader:           defaultSchemaLoader(),
	}
}

func issuerToRaw(issuer Issuer) (json.RawMessage, error) {
	return json.Marshal(issuer)
}

func (vc *Credential) validateJSONSchema(data []byte, opts *credentialOpts) error {
	return validateCredentialUsingJSONSchema(data, vc.Schemas, opts)
}

func validateCredentialUsingJSONSchema(data []byte, schemas []TypedID, opts *credentialOpts) error {
	// Validate that the Verifiable Credential conforms to the serialization of the Verifiable Credential data model
	// (https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential)
	schemaLoader, err := getSchemaLoader(schemas, opts)
	if err != nil {
		return err
	}

	loader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(schemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable credential")
		return errors.New(errMsg)
	}

	return nil
}

func getSchemaLoader(schemas []TypedID, opts *credentialOpts) (gojsonschema.JSONLoader, error) {
	if opts.disabledCustomSchema {
		return defaultSchemaLoader(), nil
	}

	for _, schema := range schemas {
		switch schema.Type {
		case jsonSchema2018Type:
			customSchemaData, err := getJSONSchema(schema.ID, opts)
			if err != nil {
				return nil, fmt.Errorf("load of custom credential schema from %s: %w", schema.ID, err)
			}

			return gojsonschema.NewBytesLoader(customSchemaData), nil
		default:
			logger.Warnf("unsupported credential schema: %s. Using default schema for validation", schema.Type)
		}
	}

	// If no custom schema is chosen, use default one
	return defaultSchemaLoader(), nil
}

func defaultSchemaLoader() gojsonschema.JSONLoader {
	return gojsonschema.NewStringLoader(defaultSchema)
}

func getJSONSchema(url string, opts *credentialOpts) ([]byte, error) {
	loader := opts.schemaLoader
	cache := loader.cache

	if cache == nil {
		return loadJSONSchema(url, loader.schemaDownloadClient)
	}

	// Check the cache first.
	if cachedBytes, ok := cache.Get(url); ok {
		return cachedBytes, nil
	}

	schemaBytes, err := loadJSONSchema(url, loader.schemaDownloadClient)
	if err != nil {
		return nil, err
	}

	// Put the loaded schema into cache
	cache.Put(url, schemaBytes)

	return schemaBytes, nil
}

func loadJSONSchema(url string, client *http.Client) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("load credential schema: %w", err)
	}

	defer func() {
		e := resp.Body.Close()
		if e != nil {
			logger.Errorf("closing response body failed [%v]", e)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("credential schema endpoint HTTP failure [%v]", resp.StatusCode)
	}

	var gotBody []byte

	gotBody, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("credential schema: read response body: %w", err)
	}

	return gotBody, nil
}

// JWTClaims converts Verifiable Credential into JWT Credential claims, which can be than serialized
// e.g. into JWS.
func (vc *Credential) JWTClaims(minimizeVC bool) (*JWTCredClaims, error) {
	return newJWTCredClaims(vc, minimizeVC)
}

// subjectID gets ID of single subject if present or
// returns error if there are several subjects or one without ID defined.
// It can also try to get ID from subject of struct type.
func subjectID(subject interface{}) (string, error) {
	subjectIDFn := func(subject map[string]interface{}) (string, error) {
		subjectWithID, defined := subject["id"]
		if !defined {
			return "", errors.New("subject id is not defined")
		}

		subjectID, isString := subjectWithID.(string)
		if !isString {
			return "", errors.New("subject id is not string")
		}

		return subjectID, nil
	}

	switch subject := subject.(type) {
	case map[string]interface{}:
		return subjectIDFn(subject)

	case []map[string]interface{}:
		if len(subject) == 0 {
			return "", errors.New("no subject is defined")
		}

		if len(subject) > 1 {
			return "", errors.New("more than one subject is defined")
		}

		return subjectIDFn(subject[0])

	case string:
		return subject, nil

	default:
		// convert to map and try once again
		sMap, err := toMap(subject)
		if err != nil {
			return "", errors.New("subject of unknown structure")
		}

		return subjectID(sMap)
	}
}

func (vc *Credential) raw() (*rawCredential, error) {
	rawRefreshService, err := typedIDsToRaw(vc.RefreshService)
	if err != nil {
		return nil, err
	}

	rawTermsOfUse, err := typedIDsToRaw(vc.TermsOfUse)
	if err != nil {
		return nil, err
	}

	proof, err := proofsToRaw(vc.Proofs)
	if err != nil {
		return nil, err
	}

	var schema interface{}
	if len(vc.Schemas) > 0 {
		schema = vc.Schemas
	}

	issuer, err := issuerToRaw(vc.Issuer)
	if err != nil {
		return nil, err
	}

	r := &rawCredential{
		Context:        contextToRaw(vc.Context, vc.CustomContext),
		ID:             vc.ID,
		Type:           typesToRaw(vc.Types),
		Subject:        vc.Subject,
		Proof:          proof,
		Status:         vc.Status,
		Issuer:         issuer,
		Schema:         schema,
		Evidence:       vc.Evidence,
		RefreshService: rawRefreshService,
		TermsOfUse:     rawTermsOfUse,
		CustomFields:   vc.CustomFields,
	}

	if vc.Issued != nil {
		r.Issued = vc.rawFields.GetIssuanceDate(vc.Issued)
	}

	if vc.Expired != nil {
		r.Expired = vc.rawFields.GetExpirationDate(vc.Expired)
	}

	return r, nil
}

func typesToRaw(types []string) interface{} {
	if len(types) == 1 {
		// as string
		return types[0]
	}
	// as string array
	return types
}

func contextToRaw(context []string, cContext []interface{}) interface{} {
	if len(cContext) > 0 {
		// return as array
		sContext := make([]interface{}, len(context), len(context)+len(cContext))
		for i := range context {
			sContext[i] = context[i]
		}

		sContext = append(sContext, cContext...)

		return sContext
	}

	return context
}

func typedIDsToRaw(typedIDs []TypedID) ([]byte, error) {
	switch len(typedIDs) {
	case 0:
		return nil, nil
	case 1:
		return json.Marshal(typedIDs[0])
	default:
		return json.Marshal(typedIDs)
	}
}

// MarshalJSON converts Verifiable Credential to JSON bytes
func (vc *Credential) MarshalJSON() ([]byte, error) {
	raw, err := vc.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}

// Presentation encloses credential into presentation.
func (vc *Credential) Presentation() (*Presentation, error) {
	vp := Presentation{
		Context: []string{baseContext},
		Type:    []string{vpType},
	}

	err := vp.SetCredentials(vc)
	if err != nil {
		return nil, fmt.Errorf("build presentation from credential: %w", err)
	}

	return &vp, nil
}
