/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.
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
	"crypto"
	"time"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/spi/kms"
	"github.com/hyperledger/aries-framework-go/spi/vdr"

	"github.com/hyperledger/aries-framework-go/component/models/dataintegrity"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
)

// DefaultSchemaTemplate describes default schema.
const DefaultSchemaTemplate = verifiable.DefaultSchemaTemplate

// SchemaCache defines a cache of credential schemas.
type SchemaCache = verifiable.SchemaCache

// ExpirableSchemaCache is an implementation of SchemaCache based fastcache.Cache with expirable elements.
type ExpirableSchemaCache = verifiable.ExpirableSchemaCache

// CredentialSchemaLoader defines expirable cache.
type CredentialSchemaLoader = verifiable.CredentialSchemaLoader

// CredentialSchemaLoaderBuilder defines a builder of CredentialSchemaLoader.
type CredentialSchemaLoaderBuilder = verifiable.CredentialSchemaLoaderBuilder

// NewCredentialSchemaLoaderBuilder creates a new instance of CredentialSchemaLoaderBuilder.
func NewCredentialSchemaLoaderBuilder() *CredentialSchemaLoaderBuilder {
	return verifiable.NewCredentialSchemaLoaderBuilder()
}

// Evidence defines evidence of Verifiable Credential.
type Evidence interface{}

// Issuer of the Verifiable Credential.
type Issuer = verifiable.Issuer

// Subject of the Verifiable Credential.
type Subject = verifiable.Subject

// Credential Verifiable Credential definition.
type Credential = verifiable.Credential

// CredentialDecoder makes a custom decoding of Verifiable Credential in JSON form to existent
// instance of Credential.
type CredentialDecoder = verifiable.CredentialDecoder

// CredentialTemplate defines a factory method to create new Credential template.
type CredentialTemplate = verifiable.CredentialTemplate

// CredentialOpt is the Verifiable Credential decoding option.
type CredentialOpt = verifiable.CredentialOpt

const (
	// ContextURI is the required JSON-LD context for VCs and VPs.
	ContextURI = verifiable.ContextURI
	// ContextID is the non-fragment part of the JSON-LD schema ID for VCs and VPs.
	ContextID = verifiable.ContextID
	// VCType is the required Type for Verifiable Credentials.
	VCType = verifiable.VCType
	// VPType is the required Type for Verifiable Credentials.
	VPType = verifiable.VPType
)

// WithDisabledProofCheck option for disabling of proof check.
func WithDisabledProofCheck() CredentialOpt {
	return verifiable.WithDisabledProofCheck()
}

// WithCredDisableValidation options for disabling of JSON-LD and json-schema validation.
func WithCredDisableValidation() CredentialOpt {
	return verifiable.WithCredDisableValidation()
}

// WithSchema option to set custom schema.
func WithSchema(schema string) CredentialOpt {
	return verifiable.WithSchema(schema)
}

// WithNoCustomSchemaCheck option is for disabling of Credential Schemas download if defined
// in Verifiable Credential. Instead, the Verifiable Credential is checked against default Schema.
func WithNoCustomSchemaCheck() CredentialOpt {
	return verifiable.WithNoCustomSchemaCheck()
}

// WithPublicKeyFetcher set public key fetcher used when decoding from JWS.
func WithPublicKeyFetcher(fetcher PublicKeyFetcher) CredentialOpt {
	return verifiable.WithPublicKeyFetcher(fetcher)
}

// WithCredentialSchemaLoader option is used to define custom credentials schema loader.
// If not defined, the default one is created with default HTTP client to download the schema
// and no caching of the schemas.
func WithCredentialSchemaLoader(loader *CredentialSchemaLoader) CredentialOpt {
	return verifiable.WithCredentialSchemaLoader(loader)
}

// WithJSONLDValidation uses the JSON LD parser for validation.
func WithJSONLDValidation() CredentialOpt {
	return verifiable.WithJSONLDValidation()
}

// WithBaseContextValidation validates that only the fields and values (when applicable) are present
// in the document. No extra fields are allowed (outside of credentialSubject).
func WithBaseContextValidation() CredentialOpt {
	return verifiable.WithBaseContextValidation()
}

// WithDataIntegrityVerifier provides the Data Integrity verifier to use when
// the credential being processed has a Data Integrity proof.
func WithDataIntegrityVerifier(v *dataintegrity.Verifier) CredentialOpt {
	return verifiable.WithDataIntegrityVerifier(v)
}

// WithExpectedDataIntegrityFields validates that a Data Integrity proof has the
// given purpose, domain, and challenge. Empty purpose means the default,
// assertionMethod, will be expected. Empty domain and challenge will mean they
// are not checked.
func WithExpectedDataIntegrityFields(purpose, domain, challenge string) CredentialOpt {
	return verifiable.WithExpectedDataIntegrityFields(purpose, domain, challenge)
}

// WithBaseContextExtendedValidation validates that fields that are specified in base context are as specified.
// Additional fields are allowed.
func WithBaseContextExtendedValidation(customContexts, customTypes []string) CredentialOpt {
	return verifiable.WithBaseContextExtendedValidation(customContexts, customTypes)
}

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) CredentialOpt {
	return verifiable.WithJSONLDDocumentLoader(documentLoader)
}

// WithStrictValidation enabled strict validation of VC.
//
// In case of JSON Schema validation, additionalProperties=true is set on the schema.
//
// In case of JSON-LD validation, the comparison of JSON-LD VC document after compaction with original VC one is made.
// In case of mismatch a validation exception is raised.
func WithStrictValidation() CredentialOpt {
	return verifiable.WithStrictValidation()
}

// WithExternalJSONLDContext defines external JSON-LD contexts to be used in JSON-LD validation and
// Linked Data Signatures verification.
func WithExternalJSONLDContext(context ...string) CredentialOpt {
	return verifiable.WithExternalJSONLDContext(context...)
}

// WithJSONLDOnlyValidRDF indicates the need to remove all invalid RDF dataset from normalize document
// when verifying linked data signatures of verifiable credential.
func WithJSONLDOnlyValidRDF() CredentialOpt {
	return verifiable.WithJSONLDOnlyValidRDF()
}

// WithEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VC.
func WithEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) CredentialOpt {
	return verifiable.WithEmbeddedSignatureSuites(suites...)
}

// ParseCredential parses Verifiable Credential from bytes which could be marshalled JSON or serialized JWT.
// It also applies miscellaneous options like settings of schema validation.
// It returns decoded Credential.
func ParseCredential(vcData []byte, opts ...CredentialOpt) (*Credential, error) { // nolint:funlen
	return verifiable.ParseCredential(vcData, opts...)
}

// CustomCredentialProducer is a factory for Credentials with extended data model.
type CustomCredentialProducer = verifiable.CustomCredentialProducer

// CreateCustomCredential creates custom extended credentials from bytes which could be marshalled JSON
// or serialized JWT. It parses input bytes to the base Verifiable Credential using ParseCredential().
// It then checks all producers to find the capable one to build extended Credential data model.
// If none of producers accept the credential, the base credential is returned.
func CreateCustomCredential(vcData []byte, producers []CustomCredentialProducer,
	opts ...CredentialOpt) (interface{}, error) {
	return verifiable.CreateCustomCredential(vcData, producers, opts...)
}

// JWTVCToJSON parses a JWT VC without verifying, and returns the JSON VC contents.
func JWTVCToJSON(vc []byte) ([]byte, error) {
	return verifiable.JWTVCToJSON(vc)
}

// SchemaOpt is create default schema options.
type SchemaOpt = verifiable.SchemaOpt

// WithDisableRequiredField disabled check of required field in default schema.
func WithDisableRequiredField(fieldName string) SchemaOpt {
	return verifiable.WithDisableRequiredField(fieldName)
}

// JSONSchemaLoader creates default schema with the option to disable the check of specific properties.
func JSONSchemaLoader(opts ...SchemaOpt) string {
	return verifiable.JSONSchemaLoader(opts...)
}

// SubjectID gets ID of single subject if present or
// returns error if there are several subjects or one without ID defined.
// It can also try to get ID from subject of struct type.
func SubjectID(subject interface{}) (string, error) { // nolint:gocyclo
	return verifiable.SubjectID(subject)
}

// NewExpirableSchemaCache creates new instance of ExpirableSchemaCache.
func NewExpirableSchemaCache(size int, expiration time.Duration) *ExpirableSchemaCache {
	return verifiable.NewExpirableSchemaCache(size, expiration)
}

// JWSAlgorithm defines JWT signature algorithms of Verifiable Credential.
type JWSAlgorithm = verifiable.JWSAlgorithm

// TODO https://github.com/square/go-jose/issues/263 support ES256K

const (
	// RS256 JWT Algorithm.
	RS256 = verifiable.RS256

	// PS256 JWT Algorithm.
	PS256 = verifiable.PS256

	// EdDSA JWT Algorithm.
	EdDSA = verifiable.EdDSA

	// ECDSASecp256k1 JWT Algorithm.
	ECDSASecp256k1 = verifiable.ECDSASecp256k1

	// ECDSASecp256r1 JWT Algorithm.
	ECDSASecp256r1 = verifiable.ECDSASecp256r1

	// ECDSASecp384r1 JWT Algorithm.
	ECDSASecp384r1 = verifiable.ECDSASecp384r1

	// ECDSASecp521r1 JWT Algorithm.
	ECDSASecp521r1 = verifiable.ECDSASecp521r1
)

// KeyTypeToJWSAlgo returns the JWSAlgorithm based on keyType.
func KeyTypeToJWSAlgo(keyType kms.KeyType) (JWSAlgorithm, error) {
	return verifiable.KeyTypeToJWSAlgo(keyType)
}

// PublicKeyFetcher fetches public key for JWT signing verification based on Issuer ID (possibly DID)
// and Key ID.
// If not defined, JWT encoding is not tested.
type PublicKeyFetcher = verifiable.PublicKeyFetcher

// SingleKey defines the case when only one verification key is used and we don't need to pick the one.
func SingleKey(pubKey []byte, pubKeyType string) PublicKeyFetcher {
	return verifiable.SingleKey(pubKey, pubKeyType)
}

// VDRKeyResolver resolves DID in order to find public keys for VC verification using vdr.Registry.
// A source of DID could be issuer of VC or holder of VP. It can be also obtained from
// JWS "issuer" claim or "verificationMethod" of Linked Data Proof.
type VDRKeyResolver = verifiable.VDRKeyResolver

type didResolver interface {
	Resolve(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

// NewVDRKeyResolver creates VDRKeyResolver.
func NewVDRKeyResolver(vdr didResolver) *VDRKeyResolver {
	return verifiable.NewVDRKeyResolver(vdr)
}

// Proof defines embedded proof of Verifiable Credential.
type Proof = verifiable.Proof

// CustomFields is a map of extra fields of struct build when unmarshalling JSON which are not
// mapped to the struct fields.
type CustomFields = verifiable.CustomFields

// TypedID defines a flexible structure with id and name fields and arbitrary extra fields
// kept in CustomFields.
type TypedID = verifiable.TypedID

// JWTCredClaims is JWT Claims extension by Verifiable Credential (with custom "vc" claim).
type JWTCredClaims = verifiable.JWTCredClaims

// JWTCredClaimsUnmarshaller unmarshals verifiable credential bytes into JWT claims with extra "vc" claim.
type JWTCredClaimsUnmarshaller = verifiable.JWTCredClaimsUnmarshaller

// MarshalDisclosureOption provides an option for Credential.MarshalWithDisclosure.
type MarshalDisclosureOption = verifiable.MarshalDisclosureOption

// TODO: should DiscloseGiven(IfAvailable|Required) have path semantics for disclosure?

// DiscloseGivenIfAvailable sets that the disclosures with the given claim names will be disclosed by
// Credential.MarshalWithDisclosure.
//
// If any name provided does not have a matching disclosure, Credential.MarshalWithDisclosure will skip the name.
//
// Will result in an error if this option is provided alongside DiscloseAll.
func DiscloseGivenIfAvailable(disclosureNames []string) MarshalDisclosureOption {
	return verifiable.DiscloseGivenIfAvailable(disclosureNames)
}

// DiscloseGivenRequired sets that the disclosures with the given claim names will be disclosed by
// Credential.MarshalWithDisclosure.
//
// If any name provided does not have a matching disclosure, Credential.MarshalWithDisclosure will return an error.
//
// Will result in an error if this option is provided alongside DiscloseAll.
func DiscloseGivenRequired(disclosureNames []string) MarshalDisclosureOption {
	return verifiable.DiscloseGivenRequired(disclosureNames)
}

// DiscloseAll sets that all disclosures in the given Credential will be disclosed by Credential.MarshalWithDisclosure.
//
// Will result in an error if this option is provided alongside DiscloseGivenIfAvailable or DiscloseGivenRequired.
func DiscloseAll() MarshalDisclosureOption {
	return verifiable.DiscloseAll()
}

// DisclosureHolderBinding option configures Credential.MarshalWithDisclosure to include a holder binding.
func DisclosureHolderBinding(binding *holder.BindingInfo) MarshalDisclosureOption {
	return verifiable.DisclosureHolderBinding(binding)
}

// DisclosureSigner option provides Credential.MarshalWithDisclosure with a signer that will be used to create an SD-JWT
// if the given Credential wasn't already parsed from SD-JWT.
func DisclosureSigner(signer jose.Signer, signingKeyID string) MarshalDisclosureOption {
	return verifiable.DisclosureSigner(signer, signingKeyID)
}

// MarshalWithSDJWTVersion sets version for SD-JWT VC.
func MarshalWithSDJWTVersion(version common.SDJWTVersion) MarshalDisclosureOption {
	return verifiable.MarshalWithSDJWTVersion(version)
}

// MakeSDJWTOption provides an option for creating an SD-JWT from a VC.
type MakeSDJWTOption = verifiable.MakeSDJWTOption

// MakeSDJWTWithHash sets the hash to use for an SD-JWT VC.
func MakeSDJWTWithHash(hash crypto.Hash) MakeSDJWTOption {
	return verifiable.MakeSDJWTWithHash(hash)
}

// MakeSDJWTWithVersion sets version for SD-JWT VC.
func MakeSDJWTWithVersion(version common.SDJWTVersion) MakeSDJWTOption {
	return verifiable.MakeSDJWTWithVersion(version)
}

// MakeSDJWTWithRecursiveClaimsObjects sets version for SD-JWT VC. SD-JWT v5+ support.
func MakeSDJWTWithRecursiveClaimsObjects(recursiveClaimsObject []string) MakeSDJWTOption {
	return verifiable.MakeSDJWTWithRecursiveClaimsObjects(recursiveClaimsObject)
}

// MakeSDJWTWithAlwaysIncludeObjects is an option for provide object keys that should be a part of
// selectively disclosable claims.
func MakeSDJWTWithAlwaysIncludeObjects(alwaysIncludeObjects []string) MakeSDJWTOption {
	return verifiable.MakeSDJWTWithAlwaysIncludeObjects(alwaysIncludeObjects)
}

// MakeSDJWTWithNonSelectivelyDisclosableClaims is an option for provide claim names
// that should be ignored when creating selectively disclosable claims.
func MakeSDJWTWithNonSelectivelyDisclosableClaims(nonSDClaims []string) MakeSDJWTOption {
	return verifiable.MakeSDJWTWithNonSelectivelyDisclosableClaims(nonSDClaims)
}

// DisplayCredentialOption provides an option for Credential.CreateDisplayCredential.
type DisplayCredentialOption = verifiable.DisplayCredentialOption

// DisplayAllDisclosures sets that Credential.CreateDisplayCredential will include all disclosures in the generated
// credential.
func DisplayAllDisclosures() DisplayCredentialOption {
	return verifiable.DisplayAllDisclosures()
}

// DisplayGivenDisclosures sets that Credential.CreateDisplayCredential will include only the given disclosures in the
// generated credential.
func DisplayGivenDisclosures(given []string) DisplayCredentialOption {
	return verifiable.DisplayGivenDisclosures(given)
}

// Signer defines signer interface which is used to sign VC JWT.
type Signer = verifiable.Signer

// JwtSigner implement jose.Signer interface.
type JwtSigner = verifiable.JwtSigner

// GetJWTSigner returns JWT Signer.
func GetJWTSigner(signer Signer, algorithm string) *JwtSigner {
	return verifiable.GetJWTSigner(signer, algorithm)
}

// SignatureRepresentation is a signature value holder type (e.g. "proofValue" or "jws").
type SignatureRepresentation = verifiable.SignatureRepresentation

const (
	// SignatureProofValue uses "proofValue" field in a Proof to put/read a digital signature.
	SignatureProofValue = verifiable.SignatureProofValue

	// SignatureJWS uses "jws" field in a Proof as an element for representation of detached JSON Web Signatures.
	SignatureJWS = verifiable.SignatureJWS
)

// LinkedDataProofContext holds options needed to build a Linked Data Proof.
type LinkedDataProofContext = verifiable.LinkedDataProofContext

// MarshalledCredential defines marshalled Verifiable Credential enclosed into Presentation.
// MarshalledCredential can be passed to verifiable.ParseCredential().
type MarshalledCredential = verifiable.MarshalledCredential

// CreatePresentationOpt are options for creating a new presentation.
type CreatePresentationOpt = verifiable.CreatePresentationOpt

// Presentation Verifiable Presentation base data model definition.
type Presentation = verifiable.Presentation

// NewPresentation creates a new Presentation with default context and type with the provided credentials.
func NewPresentation(opts ...CreatePresentationOpt) (*Presentation, error) {
	return verifiable.NewPresentation(opts...)
}

// WithCredentials sets the provided credentials into the presentation.
func WithCredentials(cs ...*Credential) CreatePresentationOpt {
	return verifiable.WithCredentials(cs...)
}

// WithJWTCredentials sets the provided base64url encoded JWT credentials into the presentation.
func WithJWTCredentials(cs ...string) CreatePresentationOpt {
	return verifiable.WithJWTCredentials(cs...)
}

// PresentationOpt is the Verifiable Presentation decoding option.
type PresentationOpt = verifiable.PresentationOpt

// WithPresPublicKeyFetcher indicates that Verifiable Presentation should be decoded from JWS using
// the public key fetcher.
func WithPresPublicKeyFetcher(fetcher PublicKeyFetcher) PresentationOpt {
	return verifiable.WithPresPublicKeyFetcher(fetcher)
}

// WithPresEmbeddedSignatureSuites defines the suites which are used to check embedded linked data proof of VP.
func WithPresEmbeddedSignatureSuites(suites ...verifier.SignatureSuite) PresentationOpt {
	return verifiable.WithPresEmbeddedSignatureSuites(suites...)
}

// WithPresDisabledProofCheck option for disabling of proof check.
func WithPresDisabledProofCheck() PresentationOpt {
	return verifiable.WithPresDisabledProofCheck()
}

// WithPresStrictValidation enabled strict JSON-LD validation of VP.
// In case of JSON-LD validation, the comparison of JSON-LD VP document after compaction with original VP one is made.
// In case of mismatch a validation exception is raised.
func WithPresStrictValidation() PresentationOpt {
	return verifiable.WithPresStrictValidation()
}

// WithPresJSONLDDocumentLoader defines custom JSON-LD document loader. If not defined, when decoding VP
// a new document loader will be created using CachingJSONLDLoader() if JSON-LD validation is made.
func WithPresJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) PresentationOpt {
	return verifiable.WithPresJSONLDDocumentLoader(documentLoader)
}

// WithDisabledJSONLDChecks disables JSON-LD checks for VP parsing.
// By default, JSON-LD checks are enabled.
func WithDisabledJSONLDChecks() PresentationOpt {
	return verifiable.WithDisabledJSONLDChecks()
}

// ParsePresentation creates an instance of Verifiable Presentation by reading a JSON document from bytes.
// It also applies miscellaneous options like custom decoders or settings of schema validation.
func ParsePresentation(vpData []byte, opts ...PresentationOpt) (*Presentation, error) {
	return verifiable.ParsePresentation(vpData, opts...)
}

// JWTPresClaims is JWT Claims extension by Verifiable Presentation (with custom "vp" claim).
type JWTPresClaims = verifiable.JWTPresClaims

// JWTPresClaimsUnmarshaller parses JWT of certain type to JWT Claims containing "vp" (Presentation) claim.
type JWTPresClaimsUnmarshaller = verifiable.JWTPresClaimsUnmarshaller
