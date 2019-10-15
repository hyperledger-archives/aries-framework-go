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

// CredentialStatus defines status of Verifiable Credential
type CredentialStatus typedID

// CredentialSchema defines a link to data schema which enforces a specific structure of Verifiable Credential.
type CredentialSchema typedID

// Credential Verifiable Credential definition
type Credential struct {
	Context        []interface{}
	ID             string
	Type           interface{}
	Subject        Subject
	Issuer         Issuer
	Issued         *time.Time
	Expired        *time.Time
	Proof          *Proof
	Status         *CredentialStatus
	Schemas        []CredentialSchema
	Evidence       *Evidence
	TermsOfUse     []TermsOfUse
	RefreshService *RefreshService
}

// rawCredential is a basic verifiable credential
type rawCredential struct {
	Context        []interface{}     `json:"@context,omitempty"`
	ID             string            `json:"id,omitempty"`
	Type           interface{}       `json:"type,omitempty"`
	Subject        Subject           `json:"credentialSubject,omitempty"`
	Issued         *time.Time        `json:"issuanceDate,omitempty"`
	Expired        *time.Time        `json:"expirationDate,omitempty"`
	Proof          *Proof            `json:"proof,omitempty"`
	Status         *CredentialStatus `json:"credentialStatus,omitempty"`
	Issuer         interface{}       `json:"issuer,omitempty"`
	Schema         interface{}       `json:"credentialSchema,omitempty"`
	Evidence       *Evidence         `json:"evidence,omitempty"`
	TermsOfUse     []TermsOfUse      `json:"termsOfUse,omitempty"`
	RefreshService *RefreshService   `json:"refreshService,omitempty"`
}

type typeSingle struct {
	Type string `json:"type,omitempty"`
}

type typeMultiple struct {
	Types []string `json:"type,omitempty"`
}

type credentialSchemaSingle struct {
	Schema CredentialSchema `json:"credentialSchema,omitempty"`
}

type credentialSchemaMultiple struct {
	Schemas []CredentialSchema `json:"credentialSchema,omitempty"`
}

type issuerPlain struct {
	ID string `json:"issuer,omitempty"`
}

type compositeIssuer struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

type embeddedCompositeIssuer struct {
	CompositeIssuer compositeIssuer `json:"issuer,omitempty"`
}

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder func(dataJSON []byte, credential *Credential) error

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate func() *Credential

// PublicKeyFetcher fetches public key for JWT signing verification based on Issuer ID (possibly DID)
// and Key ID.
// If not defined, JWT encoding is not tested.
type PublicKeyFetcher func(issuerID, keyID string) (interface{}, error)

// credentialOpts holds options for the Verifiable Credential decoding
type credentialOpts struct {
	schemaDownloadClient   *http.Client
	disabledCustomSchema   bool
	decoders               []CredentialDecoder
	template               CredentialTemplate
	issuerPublicKeyFetcher PublicKeyFetcher
	jwtDecoding            jwtDecoding
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

// WithDecoders option is for adding extra JSON decoders into Verifiable Credential data model.
func WithDecoders(decoders []CredentialDecoder) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.decoders = append(opts.decoders, decoders...)
	}
}

// WithTemplate option is for setting a custom factory method to create new Credential instance.
func WithTemplate(template CredentialTemplate) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.template = template
	}
}

// WithJWSDecoding indicates that Verifiable Credential should be decoded from JWS using
// the public key fetcher.
func WithJWSDecoding(fetcher PublicKeyFetcher) CredentialOpt {
	return func(opts *credentialOpts) {
		opts.issuerPublicKeyFetcher = fetcher
		opts.jwtDecoding = jwsDecoding
	}
}

// WithUnsecuredJWTDecoding indicates that Verifiable Credential should be decoded from unsecured JWT.
func WithUnsecuredJWTDecoding() CredentialOpt {
	return func(opts *credentialOpts) {
		opts.jwtDecoding = unsecuredJWTDecoding
	}
}

func decodeIssuer(data []byte, credential *Credential) error {
	issuerID, issuerName, err := issuerFromBytes(data)
	if err != nil {
		return fmt.Errorf("JSON unmarshalling of Verifiable Credential Issuer failed: %w", err)
	}

	credential.Issuer = Issuer{ID: issuerID, Name: issuerName}
	return nil
}

func decodeType(data []byte, vc *Credential) error {
	single := typeSingle{}
	err := json.Unmarshal(data, &single)
	if err == nil {
		vc.Type = single.Type
		return nil
	}

	multiple := typeMultiple{}
	err = json.Unmarshal(data, &multiple)
	if err == nil {
		vc.Type = multiple.Types
		return nil
	}

	return fmt.Errorf("JSON unmarshalling of Verifiable Credential Type failed: %w", err)
}

func decodeCredentialSchema(data []byte) ([]CredentialSchema, error) {
	single := credentialSchemaSingle{}
	err := json.Unmarshal(data, &single)
	if err == nil {
		return []CredentialSchema{single.Schema}, nil
	}

	multiple := credentialSchemaMultiple{}
	err = json.Unmarshal(data, &multiple)
	if err == nil {
		return multiple.Schemas, nil
	}

	return nil, fmt.Errorf("JSON unmarshalling of Verifiable Credential Schema failed: %w", err)
}

// NewCredential creates an instance of Verifiable Credential by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func NewCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) {
	// Apply options
	crOpts := defaultCredentialOpts()
	for _, opt := range opts {
		opt(crOpts)
	}

	vcDataDecoded, raw, err := decodeRaw(vcData, crOpts)
	if err != nil {
		return nil, err
	}

	schemas, err := loadCredentialSchemas(raw, vcDataDecoded)
	if err != nil {
		return nil, err
	}

	err = validate(vcDataDecoded, schemas, crOpts)
	if err != nil {
		return nil, err
	}

	cred := crOpts.template()
	cred.Context = raw.Context
	cred.ID = raw.ID
	cred.Subject = raw.Subject
	cred.Issued = raw.Issued
	cred.Expired = raw.Expired
	cred.Proof = raw.Proof
	cred.Status = raw.Status
	cred.Schemas = schemas
	cred.Evidence = raw.Evidence
	cred.RefreshService = raw.RefreshService
	cred.TermsOfUse = raw.TermsOfUse

	for _, decoder := range crOpts.decoders {
		err = decoder(vcDataDecoded, cred)
		if err != nil {
			return nil, err
		}
	}

	return cred, nil
}

func decodeRaw(vcData []byte, crOpts *credentialOpts) ([]byte, *rawCredential, error) {
	switch crOpts.jwtDecoding {
	case jwsDecoding:
		vcDataFromJwt, rawCred, err := decodeCredJWS(vcData, crOpts.issuerPublicKeyFetcher)
		if err != nil {
			return nil, nil, fmt.Errorf("JWS decoding failed: %w", err)
		}
		return vcDataFromJwt, rawCred, nil

	case unsecuredJWTDecoding:
		rawBytes, rawCred, err := decodeCredJWTUnsecured(vcData)
		if err != nil {
			return nil, nil, fmt.Errorf("unsecured JWT decoding failed: %w", err)
		}
		return rawBytes, rawCred, nil
	}

	// unmarshal VC from JSON
	raw := &rawCredential{}
	err := json.Unmarshal(vcData, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON unmarshalling of verifiable credential failed: %w", err)
	}
	return vcData, raw, nil
}

func loadCredentialSchemas(raw *rawCredential, vcDataDecoded []byte) ([]CredentialSchema, error) {
	if raw.Schema != nil {
		schemas, err := decodeCredentialSchema(vcDataDecoded)
		if err != nil {
			return nil, fmt.Errorf("failed to decode credential schemas: %w", err)
		}
		return schemas, nil
	}
	return []CredentialSchema{}, nil
}

func defaultCredentialOpts() *credentialOpts {
	return &credentialOpts{
		schemaDownloadClient: &http.Client{},
		disabledCustomSchema: false,
		decoders:             []CredentialDecoder{decodeIssuer, decodeType},
		template:             func() *Credential { return &Credential{} },
		jwtDecoding:          noJwtDecoding,
	}
}

func issuerFromBytes(data []byte) (issuerID, issuerName string, err error) {
	issuerPlain := &issuerPlain{}
	err = json.Unmarshal(data, &issuerPlain)
	if err == nil {
		return issuerPlain.ID, "", nil
	}

	eci := &embeddedCompositeIssuer{}
	err = json.Unmarshal(data, &eci)
	if err != nil {
		return "", "", errors.New("verifiable credential issuer is not valid")
	}

	return eci.CompositeIssuer.ID, eci.CompositeIssuer.Name, nil
}

func issuerToSerialize(vc *Credential) interface{} {
	if vc.Issuer.Name != "" {
		return &compositeIssuer{ID: vc.Issuer.ID, Name: vc.Issuer.Name}
	}
	return vc.Issuer.ID
}

func validate(data []byte, schemas []CredentialSchema, opts *credentialOpts) error {
	// Validate that the Verifiable Credential conforms to the serialization of the Verifiable Credential data model
	// (https://w3c.github.io/vc-data-model/#example-1-a-simple-example-of-a-verifiable-credential)
	schemaLoader, err := getSchemaLoader(schemas, opts)
	if err != nil {
		return err
	}

	loader := gojsonschema.NewStringLoader(string(data))
	result, err := gojsonschema.Validate(schemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential failed: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable credential")
		return errors.New(errMsg)
	}

	return nil
}

func getSchemaLoader(schemas []CredentialSchema, opts *credentialOpts) (gojsonschema.JSONLoader, error) {
	if opts.disabledCustomSchema {
		return defaultSchemaLoader, nil
	}

	for _, schema := range schemas {
		switch schema.Type {
		case jsonSchema2018Type:
			customSchemaData, err := loadCredentialSchema(schema.ID, opts.schemaDownloadClient)
			if err != nil {
				return nil, fmt.Errorf("loading custom credential schema from %s failed: %w", schema.ID, err)
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
		return nil, fmt.Errorf("HTTP request failed: %w", err)
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
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	return gotBody, nil
}

// JWTClaims converts Verifiable Credential into JWT Credential claims, which can be than serialized
// e.g. into JWS.
func (vc *Credential) JWTClaims(minimizeVc bool) (*JWTCredClaims, error) {
	return newJWTCredClaims(vc, minimizeVc)
}

// SubjectID gets ID of single subject if present or
// returns error if there are several subjects or one without ID defined
func (vc *Credential) SubjectID() (string, error) {
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

	switch subject := vc.Subject.(type) {
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
		return "", errors.New("subject of unknown structure")
	}
}

// Types returns a list containing types of minimum one string type
func (vc *Credential) Types() []string {
	switch t := vc.Type.(type) {
	case string:
		return []string{t}
	case []string:
		return t
	}
	return []string{}
}

func (vc *Credential) raw() *rawCredential {
	return &rawCredential{
		Context:        vc.Context,
		ID:             vc.ID,
		Type:           vc.Type,
		Subject:        vc.Subject,
		Issued:         vc.Issued,
		Expired:        vc.Expired,
		Proof:          vc.Proof,
		Status:         vc.Status,
		Issuer:         issuerToSerialize(vc),
		Schema:         vc.Schemas,
		Evidence:       vc.Evidence,
		RefreshService: vc.RefreshService,
		TermsOfUse:     vc.TermsOfUse,
	}
}

func (raw *rawCredential) marshalJSON() ([]byte, error) {
	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of raw verifiable credential failed: %w", err)
	}

	return byteCred, nil
}

// MarshalJSON converts Verifiable Credential to JSON bytes
func (vc *Credential) MarshalJSON() ([]byte, error) {
	byteCred, err := json.Marshal(vc.raw())
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable credential failed: %w", err)
	}

	return byteCred, nil
}
