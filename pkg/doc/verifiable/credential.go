/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
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
        }
      ]
    }
  }
}
`

const jsonSchema2018Type = "JsonSchemaValidator2018"

//nolint:gochecknoglobals
var defaultSchemaLoader = gojsonschema.NewStringLoader(defaultSchema)

// Evidence defines evidence of Verifiable Credential
type Evidence interface{}

// Issuer of the Verifiable Credential
type Issuer struct {
	ID   string
	Name string
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
	Proof          *Proof
	Status         *TypedID
	Schemas        []TypedID
	Evidence       *Evidence
	TermsOfUse     []TypedID
	RefreshService *TypedID

	CustomFields CustomFields
}

// rawCredential is a basic verifiable credential
type rawCredential struct {
	Context        interface{} `json:"@context,omitempty"`
	ID             string      `json:"id,omitempty"`
	Type           interface{} `json:"type,omitempty"`
	Subject        Subject     `json:"credentialSubject,omitempty"`
	Issued         *time.Time  `json:"issuanceDate,omitempty"`
	Expired        *time.Time  `json:"expirationDate,omitempty"`
	Proof          *Proof      `json:"proof,omitempty"`
	Status         *TypedID    `json:"credentialStatus,omitempty"`
	Issuer         interface{} `json:"issuer,omitempty"`
	Schema         interface{} `json:"credentialSchema,omitempty"`
	Evidence       *Evidence   `json:"evidence,omitempty"`
	TermsOfUse     []TypedID   `json:"termsOfUse,omitempty"`
	RefreshService *TypedID    `json:"refreshService,omitempty"`

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

type credentialSchemaSingle struct {
	Schema TypedID `json:"credentialSchema,omitempty"`
}

type credentialSchemaMultiple struct {
	Schemas []TypedID `json:"credentialSchema,omitempty"`
}

type compositeIssuer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder func(dataJSON []byte, vc *Credential) error

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate func() *Credential

// credentialOpts holds options for the Verifiable Credential decoding
type credentialOpts struct {
	schemaDownloadClient   *http.Client
	disabledCustomSchema   bool
	issuerPublicKeyFetcher PublicKeyFetcher
}

// CredentialOpt is the Verifiable Credential decoding option
type CredentialOpt func(opts *credentialOpts)

// WithSchemaDownloadClient option is for definition of HTTP(s) client used during decoding of Verifiable Credential.
// If custom credentialSchema is defined in Verifiable Credential, the client downloads from the specified URL.
func WithSchemaDownloadClient(client *http.Client) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.schemaDownloadClient = client
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
		opts.issuerPublicKeyFetcher = fetcher
	}
}

// decodeIssuer decodes raw issuer.
//
// Issuer can be defined by:
//
// - a string which is ID of the issuer;
//
// - object with mandatory "id" field and optional "name" field.
func decodeIssuer(rc *rawCredential) (Issuer, error) {
	getStringEntry := func(m map[string]interface{}, k string) (string, error) {
		v, exists := m[k]
		if !exists {
			return "", nil
		}

		s, valid := v.(string)
		if !valid {
			return "", fmt.Errorf("value of key '%s' is not a string", k)
		}

		return s, nil
	}

	switch iss := rc.Issuer.(type) {
	case string:
		return Issuer{ID: iss}, nil
	case map[string]interface{}:
		id, err := getStringEntry(iss, "id")
		if err != nil {
			return Issuer{}, err
		}

		if id == "" {
			return Issuer{}, errors.New("issuer ID is not defined")
		}

		name, err := getStringEntry(iss, "name")
		if err != nil {
			return Issuer{}, err
		}

		return Issuer{
			ID:   id,
			Name: name,
		}, nil
	default:
		return Issuer{}, errors.New("unsupported format of issuer")
	}
}

// decodeType decodes raw type(s).
//
// type can be defined as a single string value or array of strings.
func decodeType(rc *rawCredential) ([]string, error) {
	switch rType := rc.Type.(type) {
	case string:
		return []string{rType}, nil
	case []interface{}:
		types, err := stringSlice(rType)
		if err != nil {
			return nil, fmt.Errorf("vc types: %w", err)
		}

		return types, nil
	default:
		return nil, errors.New("credential type of unknown type")
	}
}

// decodeContext decodes raw context(s).
//
// context can be defined as a single string value or array;
// at the second case, the array can be a mix of string and object types
// (objects can express context information); object context are
// defined at the tail of the array.
func decodeContext(rc *rawCredential) ([]string, []interface{}, error) {
	switch rContext := rc.Context.(type) {
	case string:
		return []string{rContext}, nil, nil
	case []interface{}:
		strings := make([]string, 0)

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				// the remaining contexts are of custom type
				return strings, rContext[i:], nil
			}

			strings = append(strings, c)
		}
		// no contexts of custom type, just string contexts found
		return strings, nil, nil
	default:
		return nil, nil, errors.New("credential context of unknown type")
	}
}

// decodeCredentialSchema decodes credential schema(s).
//
// credential schema can be defined as a single object or array of objects.
func decodeCredentialSchema(data []byte) ([]TypedID, error) {
	// Credential schema is defined by
	single := credentialSchemaSingle{}

	err := json.Unmarshal(data, &single)
	if err == nil {
		return []TypedID{single.Schema}, nil
	}

	multiple := credentialSchemaMultiple{}

	err = json.Unmarshal(data, &multiple)
	if err == nil {
		return multiple.Schemas, nil
	}

	return nil, errors.New("verifiable credential schema of unsupported format")
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
	crOpts := parseCredentialOpts(opts)

	// Decode credential (e.g. from JWT).
	vcDataDecoded, err := decodeRaw(vcData, crOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("decode new credential: %w", err)
	}

	// Unmarshal raw credential from JSON.
	var raw rawCredential
	err = json.Unmarshal(vcDataDecoded, &raw)

	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal new credential: %w", err)
	}

	// Load custom credential schemas if defined.
	var schemas []TypedID
	if raw.Schema != nil {
		schemas, err = loadCredentialSchemas(vcDataDecoded)
		if err != nil {
			return nil, nil, fmt.Errorf("load schemas of new credential: %w", err)
		}
	} else {
		schemas = make([]TypedID, 0)
	}

	// Validate raw credential.
	err = validate(vcDataDecoded, schemas, crOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("validate new credential: %w", err)
	}

	// Create credential from raw.
	vc, err := newCredential(&raw, schemas)
	if err != nil {
		return nil, nil, fmt.Errorf("build new credential: %w", err)
	}

	return vc, vcDataDecoded, nil
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

func newCredential(raw *rawCredential, schemas []TypedID) (*Credential, error) {
	types, err := decodeType(raw)
	if err != nil {
		return nil, fmt.Errorf("fill credential types from raw: %w", err)
	}

	issuer, err := decodeIssuer(raw)
	if err != nil {
		return nil, fmt.Errorf("fill credential issuer from raw: %w", err)
	}

	context, customContext, err := decodeContext(raw)
	if err != nil {
		return nil, fmt.Errorf("fill credential context from raw: %w", err)
	}

	return &Credential{
		Context:        context,
		CustomContext:  customContext,
		ID:             raw.ID,
		Types:          types,
		Subject:        raw.Subject,
		Issuer:         issuer,
		Issued:         raw.Issued,
		Expired:        raw.Expired,
		Proof:          raw.Proof,
		Status:         raw.Status,
		Schemas:        schemas,
		Evidence:       raw.Evidence,
		TermsOfUse:     raw.TermsOfUse,
		RefreshService: raw.RefreshService,
		CustomFields:   raw.CustomFields,
	}, nil
}

func decodeRaw(vcData []byte, crOpts *credentialOpts) ([]byte, error) {
	if isJWS(vcData) {
		if crOpts.issuerPublicKeyFetcher == nil {
			return nil, errors.New("public key fetcher is not defined")
		}

		vcDecodedBytes, err := decodeCredJWS(vcData, crOpts.issuerPublicKeyFetcher)
		if err != nil {
			return nil, fmt.Errorf("JWS decoding: %w", err)
		}

		return vcDecodedBytes, nil
	}

	if isJWTUnsecured(vcData) {
		vcDecodedBytes, err := decodeCredJWTUnsecured(vcData)
		if err != nil {
			return nil, fmt.Errorf("unsecured JWT decoding: %w", err)
		}

		return vcDecodedBytes, nil
	}

	return vcData, nil
}

func loadCredentialSchemas(vcBytes []byte) ([]TypedID, error) {
	schemas, err := decodeCredentialSchema(vcBytes)
	if err != nil {
		return nil, fmt.Errorf("load credential schema: %w", err)
	}

	return schemas, nil
}

func parseCredentialOpts(opts []CredentialOpt) *credentialOpts {
	crOpts := defaultCredentialOpts()

	for _, opt := range opts {
		opt(crOpts)
	}

	return crOpts
}

func defaultCredentialOpts() *credentialOpts {
	return &credentialOpts{
		schemaDownloadClient: &http.Client{},
		disabledCustomSchema: false,
	}
}

func issuerToSerialize(issuer Issuer) interface{} {
	if issuer.Name != "" {
		return &compositeIssuer{ID: issuer.ID, Name: issuer.Name}
	}

	return issuer.ID
}

func validate(data []byte, schemas []TypedID, opts *credentialOpts) error {
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
		return defaultSchemaLoader, nil
	}

	for _, schema := range schemas {
		switch schema.Type {
		case jsonSchema2018Type:
			customSchemaData, err := loadCredentialSchema(schema.ID, opts.schemaDownloadClient)
			if err != nil {
				return nil, fmt.Errorf("load of custom credential schema from %s: %w", schema.ID, err)
			}

			return gojsonschema.NewBytesLoader(customSchemaData), nil
		default:
			logger.Warnf("unsupported credential schema: %s. Using default schema for validation", schema.Type)
		}
	}

	// If no custom schema is chosen, use default one
	return defaultSchemaLoader, nil
}

// todo cache credential schema (https://github.com/hyperledger/aries-framework-go/issues/185)
func loadCredentialSchema(url string, client *http.Client) ([]byte, error) {
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

	default:
		// convert to map and try once again
		sMap, err := toMap(subject)
		if err != nil {
			return "", errors.New("subject of unknown structure")
		}

		return subjectID(sMap)
	}
}

func (vc *Credential) raw() *rawCredential {
	return &rawCredential{
		Context:        contextToSerialize(vc.Context, vc.CustomContext),
		ID:             vc.ID,
		Type:           typesToSerialize(vc.Types),
		Subject:        vc.Subject,
		Issued:         vc.Issued,
		Expired:        vc.Expired,
		Proof:          vc.Proof,
		Status:         vc.Status,
		Issuer:         issuerToSerialize(vc.Issuer),
		Schema:         vc.Schemas,
		Evidence:       vc.Evidence,
		RefreshService: vc.RefreshService,
		TermsOfUse:     vc.TermsOfUse,
		CustomFields:   vc.CustomFields,
	}
}

func typesToSerialize(types []string) interface{} {
	if len(types) == 1 {
		// as string
		return types[0]
	}
	// as string array
	return types
}

func contextToSerialize(context []string, cContext []interface{}) interface{} {
	if len(cContext) > 0 {
		// return as array
		sContext := make([]interface{}, len(context), len(context)+len(cContext))
		for i := range context {
			sContext[i] = context[i]
		}

		sContext = append(sContext, cContext...)

		return sContext
	}

	if len(context) == 1 {
		return context[0] // return single context
	}

	return context
}

// MarshalJSON converts Verifiable Credential to JSON bytes
func (vc *Credential) MarshalJSON() ([]byte, error) {
	byteCred, err := json.Marshal(vc.raw())
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential: %w", err)
	}

	return byteCred, nil
}
