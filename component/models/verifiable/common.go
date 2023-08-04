/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package verifiable implements Verifiable Credential and Presentation data model
// (https://www.w3.org/TR/vc-data-model).
// It provides the data structures and functions which allow to process the Verifiable documents on different
// sides and levels. For example, an Issuer can create verifiable.Credential structure and issue it to a
// Holder in JWS form. The Holder can decode received Credential and make sure the signature is valid.
// The Holder can present the Credential to the Verifier or combine one or more Credentials into a Verifiable
// Presentation. The Verifier can decode and verify the received Credentials and Presentations.
package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/component/models/jwt/didsignjwt"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
	kmsapi "github.com/hyperledger/aries-framework-go/spi/kms"
	vdrapi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

// TODO https://github.com/square/go-jose/issues/263 support ES256K

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential.
type JWSAlgorithm int

const (
	// RS256 JWT Algorithm.
	RS256 JWSAlgorithm = iota

	// PS256 JWT Algorithm.
	PS256

	// EdDSA JWT Algorithm.
	EdDSA

	// ECDSASecp256k1 JWT Algorithm.
	ECDSASecp256k1

	// ECDSASecp256r1 JWT Algorithm.
	ECDSASecp256r1

	// ECDSASecp384r1 JWT Algorithm.
	ECDSASecp384r1

	// ECDSASecp521r1 JWT Algorithm.
	ECDSASecp521r1
)

// KeyTypeToJWSAlgo returns the JWSAlgorithm based on keyType.
func KeyTypeToJWSAlgo(keyType kmsapi.KeyType) (JWSAlgorithm, error) {
	switch keyType {
	case kmsapi.ECDSAP256TypeDER, kmsapi.ECDSAP256TypeIEEEP1363:
		return ECDSASecp256r1, nil
	case kmsapi.ECDSAP384TypeDER, kmsapi.ECDSAP384TypeIEEEP1363:
		return ECDSASecp384r1, nil
	case kmsapi.ECDSAP521TypeDER, kmsapi.ECDSAP521TypeIEEEP1363:
		return ECDSASecp521r1, nil
	case kmsapi.ED25519Type:
		return EdDSA, nil
	case kmsapi.ECDSASecp256k1TypeIEEEP1363, kmsapi.ECDSASecp256k1DER:
		return ECDSASecp256k1, nil
	case kmsapi.RSARS256Type:
		return RS256, nil
	case kmsapi.RSAPS256Type:
		return PS256, nil
	default:
		return 0, errors.New("unsupported key type")
	}
}

// Name return the name of the signature algorithm.
func (ja JWSAlgorithm) Name() (string, error) {
	switch ja {
	case RS256:
		return "RS256", nil
	case PS256:
		return "PS256", nil
	case EdDSA:
		return "EdDSA", nil
	case ECDSASecp256k1:
		return "ES256K", nil
	case ECDSASecp256r1:
		return "ES256", nil
	case ECDSASecp384r1:
		return "ES384", nil
	case ECDSASecp521r1:
		return "ES521", nil
	default:
		return "", fmt.Errorf("unsupported algorithm: %v", ja)
	}
}

type jsonldCredentialOpts struct {
	jsonldDocumentLoader ld.DocumentLoader
	externalContext      []string
	jsonldOnlyValidRDF   bool
}

// PublicKeyFetcher fetches public key for JWT signing verification based on Issuer ID (possibly DID)
// and Key ID.
// If not defined, JWT encoding is not tested.
type PublicKeyFetcher = didsignjwt.PublicKeyFetcher

// SingleKey defines the case when only one verification key is used and we don't need to pick the one.
func SingleKey(pubKey []byte, pubKeyType string) PublicKeyFetcher {
	return func(_, _ string) (*verifier.PublicKey, error) {
		return &verifier.PublicKey{
			Type:  pubKeyType,
			Value: pubKey,
		}, nil
	}
}

// VDRKeyResolver resolves DID in order to find public keys for VC verification using vdr.Registry.
// A source of DID could be issuer of VC or holder of VP. It can be also obtained from
// JWS "issuer" claim or "verificationMethod" of Linked Data Proof.
type VDRKeyResolver struct {
	vdr didResolver
}

type didResolver interface {
	Resolve(did string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)
}

// NewVDRKeyResolver creates VDRKeyResolver.
func NewVDRKeyResolver(vdr didResolver) *VDRKeyResolver {
	return &VDRKeyResolver{vdr: vdr}
}

func (r *VDRKeyResolver) resolvePublicKey(issuerDID, keyID string) (*verifier.PublicKey, error) {
	docResolution, err := r.vdr.Resolve(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", issuerDID, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) &&
				verification.Relationship != did.KeyAgreement {
				return &verifier.PublicKey{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", keyID, issuerDID)
}

// PublicKeyFetcher returns Public Key Fetcher via DID resolution mechanism.
func (r *VDRKeyResolver) PublicKeyFetcher() PublicKeyFetcher {
	return r.resolvePublicKey
}

// Proof defines embedded proof of Verifiable Credential.
type Proof map[string]interface{}

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields map[string]interface{}

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in CustomFields.
type TypedID struct {
	ID   string `json:"id,omitempty"`
	Type string `json:"type,omitempty"`

	CustomFields `json:"-"`
}

// MarshalJSON defines custom marshalling of TypedID to JSON.
func (tid TypedID) MarshalJSON() ([]byte, error) {
	// TODO hide this exported method
	type Alias TypedID

	alias := Alias(tid)

	data, err := jsonutil.MarshalWithCustomFields(alias, tid.CustomFields)
	if err != nil {
		return nil, fmt.Errorf("marshal TypedID: %w", err)
	}

	return data, nil
}

// UnmarshalJSON defines custom unmarshalling of TypedID from JSON.
func (tid *TypedID) UnmarshalJSON(data []byte) error {
	// TODO hide this exported method
	type Alias TypedID

	alias := (*Alias)(tid)

	tid.CustomFields = make(CustomFields)

	err := jsonutil.UnmarshalWithCustomFields(data, alias, tid.CustomFields)
	if err != nil {
		return fmt.Errorf("unmarshal TypedID: %w", err)
	}

	return nil
}

func newTypedID(v interface{}) (TypedID, error) {
	bytes, err := json.Marshal(v)
	if err != nil {
		return TypedID{}, err
	}

	var tid TypedID
	err = json.Unmarshal(bytes, &tid)

	return tid, err
}

func describeSchemaValidationError(result *gojsonschema.Result, what string) string {
	errMsg := what + " is not valid:\n"
	for _, desc := range result.Errors() {
		errMsg += fmt.Sprintf("- %s\n", desc)
	}

	return errMsg
}

func stringSlice(values []interface{}) ([]string, error) {
	s := make([]string, len(values))

	for i := range values {
		t, valid := values[i].(string)
		if !valid {
			return nil, errors.New("array element is not a string")
		}

		s[i] = t
	}

	return s, nil
}

// decodeType decodes raw type(s).
//
// type can be defined as a single string value or array of strings.
func decodeType(t interface{}) ([]string, error) {
	switch rType := t.(type) {
	case string:
		return []string{rType}, nil
	case []interface{}:
		types, err := stringSlice(rType)
		if err != nil {
			return nil, fmt.Errorf("vc types: %w", err)
		}

		return types, nil
	default:
		return nil, errors.New("credential type of unknown structure")
	}
}

// decodeContext decodes raw context(s).
//
// context can be defined as a single string value or array;
// at the second case, the array can be a mix of string and object types
// (objects can express context information); object context are
// defined at the tail of the array.
func decodeContext(c interface{}) ([]string, []interface{}, error) {
	switch rContext := c.(type) {
	case string:
		return []string{rContext}, nil, nil
	case []interface{}:
		s := make([]string, 0)

		for i := range rContext {
			c, valid := rContext[i].(string)
			if !valid {
				// the remaining contexts are of custom type
				return s, rContext[i:], nil
			}

			s = append(s, c)
		}
		// no contexts of custom type, just string contexts found
		return s, nil, nil
	default:
		return nil, nil, errors.New("credential context of unknown type")
	}
}

func safeStringValue(v interface{}) string {
	if v == nil {
		return ""
	}

	return v.(string)
}

func proofsToRaw(proofs []Proof) ([]byte, error) {
	switch len(proofs) {
	case 0:
		return nil, nil
	case 1:
		return json.Marshal(proofs[0])
	default:
		return json.Marshal(proofs)
	}
}

func parseProof(proofBytes json.RawMessage) ([]Proof, error) {
	if len(proofBytes) == 0 {
		return nil, nil
	}

	var singleProof Proof

	err := json.Unmarshal(proofBytes, &singleProof)
	if err == nil {
		return []Proof{singleProof}, nil
	}

	var composedProof []Proof

	err = json.Unmarshal(proofBytes, &composedProof)
	if err == nil {
		return composedProof, nil
	}

	return nil, err
}
