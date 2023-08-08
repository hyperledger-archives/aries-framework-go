/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	jsonld "github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	docjsonld "github.com/hyperledger/aries-framework-go/component/models/ld/validator"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
)

const basePresentationSchema = `
{
  "required": [
    "@context",
    "type"
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
      "type": "string"
    },
    "type": {
      "oneOf": [
        {
          "type": "array",
          "minItems": 1,
          "contains": {
            "type": "string",
            "pattern": "^VerifiablePresentation$"
          }
        },
        {
          "type": "string",
          "pattern": "^VerifiablePresentation$"
        }
      ]
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
        },
        {
          "type": "null"
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

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.ParseCredential().
type MarshalledCredential []byte

// CreatePresentationOpt are options for creating a new presentation.
type CreatePresentationOpt func(p *Presentation) error

// Presentation Verifiable Presentation base data model definition.
type Presentation struct {
	Context       []string
	CustomContext []interface{}
	ID            string
	Type          []string
	credentials   []interface{}
	Holder        string
	Proofs        []Proof
	JWT           string
	CustomFields  CustomFields
}

// NewPresentation creates a new Presentation with default context and type with the provided credentials.
func NewPresentation(opts ...CreatePresentationOpt) (*Presentation, error) {
	p := Presentation{
		Context:     []string{baseContext},
		Type:        []string{vpType},
		credentials: []interface{}{},
	}

	for _, o := range opts {
		err := o(&p)
		if err != nil {
			return nil, err
		}
	}

	return &p, nil
}

// WithCredentials sets the provided credentials into the presentation.
func WithCredentials(cs ...*Credential) CreatePresentationOpt {
	return func(p *Presentation) error {
		for _, c := range cs {
			p.credentials = append(p.credentials, c)
		}

		return nil
	}
}

// WithJWTCredentials sets the provided base64url encoded JWT credentials into the presentation.
func WithJWTCredentials(cs ...string) CreatePresentationOpt {
	return func(p *Presentation) error {
		for _, c := range cs {
			if !jose.IsCompactJWS(c) {
				return errors.New("credential is not base64url encoded JWT")
			}

			p.credentials = append(p.credentials, c)
		}

		return nil
	}
}

// MarshalJSON converts Verifiable Presentation to JSON bytes.
func (vp *Presentation) MarshalJSON() ([]byte, error) {
	if vp.JWT != "" {
		// If vc.JWT exists, marshal only the JWT, since all other values should be unchanged
		// from when the JWT was parsed.
		return []byte("\"" + vp.JWT + "\""), nil
	}

	raw, err := vp.raw()
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	byteCred, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of verifiable presentation: %w", err)
	}

	return byteCred, nil
}

// JWTClaims converts Verifiable Presentation into JWT Presentation claims, which can be than serialized
// e.g. into JWS.
func (vp *Presentation) JWTClaims(audience []string, minimizeVP bool) (*JWTPresClaims, error) {
	return newJWTPresClaims(vp, audience, minimizeVP)
}

// Credentials returns current credentials of presentation.
func (vp *Presentation) Credentials() []interface{} {
	return vp.credentials
}

// AddCredentials adds credentials to presentation.
func (vp *Presentation) AddCredentials(credentials ...*Credential) {
	for _, credential := range credentials {
		vp.credentials = append(vp.credentials, credential)
	}
}

// MarshalledCredentials provides marshalled credentials enclosed into Presentation in raw byte array format.
// They can be used to decode Credentials into struct.
func (vp *Presentation) MarshalledCredentials() ([]MarshalledCredential, error) {
	mCreds := make([]MarshalledCredential, len(vp.credentials))

	for i := range vp.credentials {
		cred := vp.credentials[i]
		switch c := cred.(type) {
		case string:
			mCreds[i] = MarshalledCredential(c)
		case []byte:
			mCreds[i] = c
		default:
			credBytes, err := json.Marshal(cred)
			if err != nil {
				return nil, fmt.Errorf("marshal credentials from presentation: %w", err)
			}

			mCreds[i] = credBytes
		}
	}

	return mCreds, nil
}

func (vp *Presentation) raw() (*rawPresentation, error) {
	proof, err := proofsToRaw(vp.Proofs)
	if err != nil {
		return nil, err
	}

	rp := &rawPresentation{
		// TODO single value contexts should be compacted as part of Issue [#1730]
		// Not compacting now to support interoperability
		Context:      vp.Context,
		ID:           vp.ID,
		Type:         typesToRaw(vp.Type),
		Holder:       vp.Holder,
		Proof:        proof,
		CustomFields: vp.CustomFields,
		JWT:          vp.JWT,
	}

	if len(vp.credentials) > 0 {
		rp.Credential = vp.credentials
	}

	return rp, nil
}

// rawPresentation is a basic verifiable credential.
type rawPresentation struct {
	Context    interface{}     `json:"@context,omitempty"`
	ID         string          `json:"id,omitempty"`
	Type       interface{}     `json:"type,omitempty"`
	Credential interface{}     `json:"verifiableCredential,omitempty"`
	Holder     string          `json:"holder,omitempty"`
	Proof      json.RawMessage `json:"proof,omitempty"`
	JWT        string          `json:"jwt,omitempty"`
	// All unmapped fields are put here.
	CustomFields `json:"-"`
}

// MarshalJSON defines custom marshalling of rawPresentation to JSON.
func (rp *rawPresentation) MarshalJSON() ([]byte, error) {
	type Alias rawPresentation

	alias := (*Alias)(rp)

	return jsonutil.MarshalWithCustomFields(alias, rp.CustomFields)
}

// UnmarshalJSON defines custom unmarshalling of rawPresentation from JSON.
func (rp *rawPresentation) UnmarshalJSON(data []byte) error {
	type Alias rawPresentation

	alias := (*Alias)(rp)
	rp.CustomFields = make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, rp.CustomFields)
	if err != nil {
		return err
	}

	return nil
}

// presentationOpts holds options for the Verifiable Presentation decoding.
type presentationOpts struct {
	publicKeyFetcher    PublicKeyFetcher
	disabledProofCheck  bool
	ldpSuites           []verifier.SignatureSuite
	strictValidation    bool
	requireVC           bool
	requireProof        bool
	disableJSONLDChecks bool
	verifyDataIntegrity *verifyDataIntegrityOpts

	jsonldCredentialOpts
}

// PresentationOpt is the Verifiable Presentation decoding option.
type PresentationOpt func(opts *presentationOpts)

// WithPresPublicKeyFetcher indicates that Verifiable Presentation should be decoded from JWS using
// the public key fetcher.
func WithPresPublicKeyFetcher(fetcher PublicKeyFetcher) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.publicKeyFetcher = fetcher
	}
}

// WithPresEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VP.
func WithPresEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.ldpSuites = suites
	}
}

// WithPresDisabledProofCheck option for disabling of proof check.
func WithPresDisabledProofCheck() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disabledProofCheck = true
	}
}

// WithPresStrictValidation enabled strict JSON-LD validation of VP.
// In case of JSON-LD validation, the comparison of JSON-LD VP document after compaction with original VP one is made.
// In case of mismatch a validation exception is raised.
func WithPresStrictValidation() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.strictValidation = true
	}
}

// WithPresJSONLDDocumentLoader defines custom JSON-LD document loader. If not defined, when decoding VP
// a new document loader will be created using CachingJSONLDLoader() if JSON-LD validation is made.
func WithPresJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithDisabledJSONLDChecks disables JSON-LD checks for VP parsing.
// By default, JSON-LD checks are enabled.
func WithDisabledJSONLDChecks() PresentationOpt {
	return func(opts *presentationOpts) {
		opts.disableJSONLDChecks = true
	}
}

// WithPresDataIntegrityVerifier provides the Data Integrity verifier to use when
// the presentation being processed has a Data Integrity proof.
func WithPresDataIntegrityVerifier(v *dataintegrity.Verifier) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Verifier = v
	}
}

// WithPresExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithPresExpectedDataIntegrityFields(purpose, domain, challenge string) PresentationOpt {
	return func(opts *presentationOpts) {
		opts.verifyDataIntegrity.Purpose = purpose
		opts.verifyDataIntegrity.Domain = domain
		opts.verifyDataIntegrity.Challenge = challenge
	}
}

// ParsePresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func ParsePresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	vpOpts := getPresentationOpts(opts)

	vpDataDecoded, vpRaw, vpJWT, err := decodeRawPresentation(vpData, vpOpts)
	if err != nil {
		return nil, err
	}

	err = validateVP(vpDataDecoded, vpOpts)
	if err != nil {
		return nil, err
	}

	p, err := newPresentation(vpRaw, vpOpts)
	if err != nil {
		return nil, err
	}

	if vpOpts.requireVC && len(p.credentials) == 0 {
		return nil, fmt.Errorf("verifiableCredential is required")
	}

	p.JWT = vpJWT

	return p, nil
}

func getPresentationOpts(opts []PresentationOpt) *presentationOpts {
	vpOpts := defaultPresentationOpts()

	for _, opt := range opts {
		opt(vpOpts)
	}

	return vpOpts
}

func newPresentation(vpRaw *rawPresentation, vpOpts *presentationOpts) (*Presentation, error) {
	types, err := decodeType(vpRaw.Type)
	if err != nil {
		return nil, fmt.Errorf("fill presentation types from raw: %w", err)
	}

	context, customContext, err := decodeContext(vpRaw.Context)
	if err != nil {
		return nil, fmt.Errorf("fill presentation contexts from raw: %w", err)
	}

	creds, err := decodeCredentials(vpRaw.Credential, vpOpts)
	if err != nil {
		return nil, fmt.Errorf("decode credentials of presentation: %w", err)
	}

	proofs, err := parseProof(vpRaw.Proof)
	if err != nil {
		return nil, fmt.Errorf("fill credential proof from raw: %w", err)
	}

	return &Presentation{
		Context:       context,
		CustomContext: customContext,
		ID:            vpRaw.ID,
		Type:          types,
		credentials:   creds,
		Holder:        vpRaw.Holder,
		Proofs:        proofs,
		CustomFields:  vpRaw.CustomFields,
	}, nil
}

// decodeCredentials decodes credential(s) embedded into presentation.
// It must be one of the following:
// 1) string - it could be credential decoded into e.g. JWS.
// 2) the same as 1) but as array - e.g. zero ore more JWS
// 3) struct (should be map[string]interface{}) representing credential data model
// 4) the same as 3) but as array - i.e. zero or more credentials structs.
func decodeCredentials(rawCred interface{}, opts *presentationOpts) ([]interface{}, error) {
	// Accept the case when VP does not have any VCs.
	if rawCred == nil {
		return nil, nil
	}

	unmarshalSingleCredFn := func(cred interface{}) (interface{}, error) {
		// Check the case when VC is defined in string format (e.g. JWT).
		// Decode credential and keep result of decoding.
		if sCred, ok := cred.(string); ok {
			bCred := []byte(sCred)

			credOpts := []CredentialOpt{
				WithPublicKeyFetcher(opts.publicKeyFetcher),
				WithEmbeddedSignatureSuites(opts.ldpSuites...),
				WithJSONLDDocumentLoader(opts.jsonldCredentialOpts.jsonldDocumentLoader),
			}

			if opts.disabledProofCheck {
				credOpts = append(credOpts, WithDisabledProofCheck())
			}

			vc, err := ParseCredential(bCred, credOpts...)

			return vc, err
		}

		// return credential in a structure format as is
		return cred, nil
	}

	switch cred := rawCred.(type) {
	case []interface{}:
		// Accept the case when VP does not have any VCs.
		if len(cred) == 0 {
			return nil, nil
		}

		// 1 or more credentials
		creds := make([]interface{}, len(cred))

		for i := range cred {
			c, err := unmarshalSingleCredFn(cred[i])
			if err != nil {
				return nil, err
			}

			creds[i] = c
		}

		return creds, nil
	default:
		// single credential
		c, err := unmarshalSingleCredFn(cred)
		if err != nil {
			return nil, err
		}

		return []interface{}{c}, nil
	}
}

func validateVP(data []byte, opts *presentationOpts) error {
	err := validateVPJSONSchema(data)
	if err != nil {
		return err
	}

	if opts.disableJSONLDChecks {
		return nil
	}

	return validateVPJSONLD(data, opts)
}

func validateVPJSONLD(vpBytes []byte, opts *presentationOpts) error {
	return docjsonld.ValidateJSONLD(string(vpBytes),
		docjsonld.WithDocumentLoader(opts.jsonldCredentialOpts.jsonldDocumentLoader),
		docjsonld.WithExternalContext(opts.jsonldCredentialOpts.externalContext),
		docjsonld.WithStrictValidation(opts.strictValidation),
	)
}

func validateVPJSONSchema(data []byte) error {
	loader := gojsonschema.NewStringLoader(string(data))

	result, err := gojsonschema.Validate(basePresentationSchemaLoader, loader)
	if err != nil {
		return fmt.Errorf("validation of verifiable credential: %w", err)
	}

	if !result.Valid() {
		errMsg := describeSchemaValidationError(result, "verifiable presentation")
		return errors.New(errMsg)
	}

	return nil
}

//nolint:gocyclo
func decodeRawPresentation(vpData []byte, vpOpts *presentationOpts) ([]byte, *rawPresentation, string, error) {
	vpStr := string(unQuote(vpData))

	if jwt.IsJWS(vpStr) {
		if !vpOpts.disabledProofCheck && vpOpts.publicKeyFetcher == nil {
			return nil, nil, "", errors.New("public key fetcher is not defined")
		}

		vcDataFromJwt, rawCred, err := decodeVPFromJWS(vpStr, !vpOpts.disabledProofCheck, vpOpts.publicKeyFetcher)
		if err != nil {
			return nil, nil, "", fmt.Errorf("decoding of Verifiable Presentation from JWS: %w", err)
		}

		return vcDataFromJwt, rawCred, vpStr, nil
	}

	embeddedProofCheckOpts := &embeddedProofCheckOpts{
		dataIntegrityOpts:    vpOpts.verifyDataIntegrity,
		publicKeyFetcher:     vpOpts.publicKeyFetcher,
		disabledProofCheck:   vpOpts.disabledProofCheck,
		ldpSuites:            vpOpts.ldpSuites,
		jsonldCredentialOpts: vpOpts.jsonldCredentialOpts,
	}

	if jwt.IsJWTUnsecured(vpStr) {
		rawBytes, rawPres, err := decodeVPFromUnsecuredJWT(vpStr)
		if err != nil {
			return nil, nil, "", fmt.Errorf("decoding of Verifiable Presentation from unsecured JWT: %w", err)
		}

		if err := checkEmbeddedProof(rawBytes, embeddedProofCheckOpts); err != nil {
			return nil, nil, "", err
		}

		return rawBytes, rawPres, "", nil
	}

	vpRaw, err := decodeVPFromJSON(vpData)
	if err != nil {
		return nil, nil, "", err
	}

	err = checkEmbeddedProof(vpData, embeddedProofCheckOpts)
	if err != nil {
		return nil, nil, "", err
	}

	// check that embedded proof is present, if not, it's not a verifiable presentation
	if vpOpts.requireProof && vpRaw.Proof == nil {
		return nil, nil, "", errors.New("embedded proof is missing")
	}

	return vpData, vpRaw, "", err
}

func decodeVPFromJSON(vpData []byte) (*rawPresentation, error) {
	// unmarshal VP from JSON
	raw := new(rawPresentation)

	err := json.Unmarshal(vpData, raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of verifiable presentation: %w", err)
	}

	return raw, nil
}

func defaultPresentationOpts() *presentationOpts {
	return &presentationOpts{
		verifyDataIntegrity: &verifyDataIntegrityOpts{},
	}
}
