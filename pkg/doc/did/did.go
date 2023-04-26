/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

import (
	"time"

	"github.com/multiformats/go-multibase"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	didmodel "github.com/hyperledger/aries-framework-go/component/models/did"
)

const (
	// ContextV1 of the DID document is the current V1 context name.
	ContextV1 = didmodel.ContextV1
	// ContextV1Old of the DID document representing the old/legacy V1 context name.
	ContextV1Old = didmodel.ContextV1Old
)

// ErrDIDDocumentNotExist error did doc not exist.
var ErrDIDDocumentNotExist = didmodel.ErrDIDDocumentNotExist

// DID is parsed according to the generic syntax: https://w3c.github.io/did-core/#generic-did-syntax
type DID = didmodel.DID

// Parse parses the string according to the generic DID syntax.
// See https://w3c.github.io/did-core/#generic-did-syntax.
func Parse(did string) (*DID, error) {
	return didmodel.Parse(did)
}

// DIDURL holds a DID URL.
type DIDURL = didmodel.DIDURL // nolint:golint

// ParseDIDURL parses a DID URL string into a DIDURL object.
func ParseDIDURL(didURL string) (*DIDURL, error) {
	return didmodel.ParseDIDURL(didURL)
}

// Context represents JSON-LD representation-specific DID-core @context, which
// must be either a string, or a list containing maps and/or strings.
type Context = didmodel.Context

// DocResolution did resolution.
type DocResolution = didmodel.DocResolution

// MethodMetadata method metadata.
type MethodMetadata = didmodel.MethodMetadata

// ProtocolOperation info.
type ProtocolOperation = didmodel.ProtocolOperation

// DocumentMetadata document metadata.
type DocumentMetadata = didmodel.DocumentMetadata

// ParseDocumentResolution parse document resolution.
func ParseDocumentResolution(data []byte) (*DocResolution, error) {
	return didmodel.ParseDocumentResolution(data)
}

// Doc DID Document definition.
type Doc = didmodel.Doc

// VerificationMethod DID doc verification method.
// The value of the verification method is defined either as raw public key bytes (Value field) or as JSON Web Key.
// In the first case the Type field can hold additional information to understand the nature of the raw public key.
type VerificationMethod = didmodel.VerificationMethod

// NewVerificationMethodFromBytesWithMultibase creates a new VerificationMethod based on
// raw public key bytes with multibase.
func NewVerificationMethodFromBytesWithMultibase(id, keyType, controller string, value []byte,
	encoding multibase.Encoding) *VerificationMethod {
	return didmodel.NewVerificationMethodFromBytesWithMultibase(id, keyType, controller, value, encoding)
}

// NewVerificationMethodFromBytes creates a new VerificationMethod based on raw public key bytes.
func NewVerificationMethodFromBytes(id, keyType, controller string, value []byte) *VerificationMethod {
	return didmodel.NewVerificationMethodFromBytes(id, keyType, controller, value)
}

// NewVerificationMethodFromJWK creates a new VerificationMethod based on JSON Web Key.
func NewVerificationMethodFromJWK(id, keyType, controller string, j *jwk.JWK) (*VerificationMethod, error) {
	return didmodel.NewVerificationMethodFromJWK(id, keyType, controller, j)
}

// Service DID doc service.
type Service = didmodel.Service

// VerificationRelationship defines a verification relationship between DID subject and a verification method.
type VerificationRelationship = didmodel.VerificationRelationship

const (
	// VerificationRelationshipGeneral is a special case of verification relationship: when a verification method
	// defined in Verification is not used by any Verification.
	VerificationRelationshipGeneral = didmodel.VerificationRelationshipGeneral

	// Authentication defines verification relationship.
	Authentication = didmodel.Authentication

	// AssertionMethod defines verification relationship.
	AssertionMethod = didmodel.AssertionMethod

	// CapabilityDelegation defines verification relationship.
	CapabilityDelegation = didmodel.CapabilityDelegation

	// CapabilityInvocation defines verification relationship.
	CapabilityInvocation = didmodel.CapabilityInvocation

	// KeyAgreement defines verification relationship.
	KeyAgreement = didmodel.KeyAgreement
)

// Verification authentication verification.
type Verification = didmodel.Verification

// NewEmbeddedVerification creates a new verification method with embedded verification method.
func NewEmbeddedVerification(vm *VerificationMethod, r VerificationRelationship) *Verification {
	return didmodel.NewEmbeddedVerification(vm, r)
}

// NewReferencedVerification creates a new verification method with referenced verification method.
func NewReferencedVerification(vm *VerificationMethod, r VerificationRelationship) *Verification {
	return didmodel.NewReferencedVerification(vm, r)
}

// Proof is cryptographic proof of the integrity of the DID Document.
type Proof = didmodel.Proof

// ParseDocument creates an instance of DIDDocument by reading a JSON document from bytes.
func ParseDocument(data []byte) (*Doc, error) { // nolint:funlen,gocyclo
	return didmodel.ParseDocument(data)
}

// ErrProofNotFound is returned when proof is not found.
var ErrProofNotFound = didmodel.ErrProofNotFound

// ErrKeyNotFound is returned when key is not found.
var ErrKeyNotFound = didmodel.ErrKeyNotFound

// DocOption provides options to build DID Doc.
type DocOption = didmodel.DocOption

// WithVerificationMethod DID doc VerificationMethod.
func WithVerificationMethod(pubKey []VerificationMethod) DocOption {
	return didmodel.WithVerificationMethod(pubKey)
}

// WithAuthentication sets the verification methods for authentication: https://w3c.github.io/did-core/#authentication.
func WithAuthentication(auth []Verification) DocOption {
	return didmodel.WithAuthentication(auth)
}

// WithAssertion sets the verification methods for assertion: https://w3c.github.io/did-core/#assertion.
func WithAssertion(assertion []Verification) DocOption {
	return didmodel.WithAssertion(assertion)
}

// WithKeyAgreement sets the verification methods for KeyAgreement: https://w3c.github.io/did-core/#key-agreement.
func WithKeyAgreement(keyAgreement []Verification) DocOption {
	return didmodel.WithKeyAgreement(keyAgreement)
}

// WithService DID doc services.
func WithService(svc []Service) DocOption {
	return didmodel.WithService(svc)
}

// WithCreatedTime DID doc created time.
func WithCreatedTime(t time.Time) DocOption {
	return didmodel.WithCreatedTime(t)
}

// WithUpdatedTime DID doc updated time.
func WithUpdatedTime(t time.Time) DocOption {
	return didmodel.WithUpdatedTime(t)
}

// BuildDoc creates the DID Doc from options.
func BuildDoc(opts ...DocOption) *Doc {
	return didmodel.BuildDoc(opts...)
}

// LookupService returns the service from the given DIDDoc matching the given service type.
func LookupService(didDoc *Doc, serviceType string) (*Service, bool) {
	return didmodel.LookupService(didDoc, serviceType)
}

// LookupDIDCommRecipientKeys gets the DIDComm recipient keys from the did doc which match the given parameters.
// DIDComm recipient keys are encoded as did:key identifiers.
// See:
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0067-didcomm-diddoc-conventions/README.md
// - https://github.com/hyperledger/aries-rfcs/blob/master/features/0360-use-did-key/README.md
func LookupDIDCommRecipientKeys(didDoc *Doc) ([]string, bool) {
	return didmodel.LookupDIDCommRecipientKeys(didDoc)
}

// LookupPublicKey returns the public key with the given id from the given DID Doc.
func LookupPublicKey(id string, didDoc *Doc) (*VerificationMethod, bool) {
	return didmodel.LookupPublicKey(id, didDoc)
}
