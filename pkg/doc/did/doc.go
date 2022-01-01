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
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const (
	// ContextV1 of the DID document is the current V1 context name.
	ContextV1 = "https://www.w3.org/ns/did/v1"
	// ContextV1Old of the DID document representing the old/legacy V1 context name.
	ContextV1Old        = "https://w3id.org/did/v1"
	contextV011         = "https://w3id.org/did/v0.11"
	contextV12019       = "https://www.w3.org/2019/did/v1"
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
	jsonldProofPurpose   = "proofPurpose"

	// various public key encodings.
	jsonldPublicKeyBase58 = "publicKeyBase58"
	jsonldPublicKeyHex    = "publicKeyHex"
	jsonldPublicKeyPem    = "publicKeyPem"
	jsonldPublicKeyjwk    = "publicKeyJwk"
)

var (
	schemaLoaderV1     = gojsonschema.NewStringLoader(schemaV1)     //nolint:gochecknoglobals
	schemaLoaderV011   = gojsonschema.NewStringLoader(schemaV011)   //nolint:gochecknoglobals
	schemaLoaderV12019 = gojsonschema.NewStringLoader(schemaV12019) //nolint:gochecknoglobals
)

// ErrDIDDocumentNotExist error did doc not exist.
var ErrDIDDocumentNotExist = errors.New("did document not exists")

// DID is parsed according to the generic syntax: https://w3c.github.io/did-core/#generic-did-syntax
type DID struct {
	Scheme           string // Scheme is always "did"
	Method           string // Method is the specific DID methods
	MethodSpecificID string // MethodSpecificID is the unique ID computed or assigned by the DID method
}

// String returns a string representation of this DID.
func (d *DID) String() string {
	return fmt.Sprintf("%s:%s:%s", d.Scheme, d.Method, d.MethodSpecificID)
}

// Parse parses the string according to the generic DID syntax.
// See https://w3c.github.io/did-core/#generic-did-syntax.
func Parse(did string) (*DID, error) {
	// I could not find a good ABNF parser :(
	const idchar = `a-zA-Z0-9-_\.`
	regex := fmt.Sprintf(`^did:[a-z0-9]+:(:+|[:%s]+)*[%%:%s]+[^:]$`, idchar, idchar)

	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex=%s (this should not have happened!). %w", regex, err)
	}

	if !r.MatchString(did) {
		return nil, fmt.Errorf(
			"invalid did: %s. Make sure it conforms to the DID syntax: https://w3c.github.io/did-core/#did-syntax", did)
	}

	parts := strings.SplitN(did, ":", 3)

	return &DID{
		Scheme:           "did",
		Method:           parts[1],
		MethodSpecificID: parts[2],
	}, nil
}

// DIDURL holds a DID URL.
type DIDURL struct { // nolint:golint // ignore name stutter
	DID
	Path     string
	Queries  map[string][]string
	Fragment string
}

// ParseDIDURL parses a DID URL string into a DIDURL object.
func ParseDIDURL(didURL string) (*DIDURL, error) {
	split := strings.IndexAny(didURL, "?/#")

	didPart := didURL
	pathQueryFragment := ""

	if split != -1 {
		didPart = didURL[:split]
		pathQueryFragment = didURL[split:]
	}

	retDID, err := Parse(didPart)
	if err != nil {
		return nil, err
	}

	if pathQueryFragment == "" {
		return &DIDURL{
			DID:     *retDID,
			Queries: map[string][]string{},
		}, nil
	}

	hasPath := pathQueryFragment[0] == '/'

	if !hasPath {
		pathQueryFragment = "/" + pathQueryFragment
	}

	urlParts, err := url.Parse(pathQueryFragment)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path, query, and fragment components of DID URL: %w", err)
	}

	ret := &DIDURL{
		DID:      *retDID,
		Queries:  urlParts.Query(),
		Fragment: urlParts.Fragment,
	}

	if hasPath {
		ret.Path = urlParts.Path
	}

	return ret, nil
}

// DocResolution did resolution.
type DocResolution struct {
	Context          []string
	DIDDocument      *Doc
	DocumentMetadata *DocumentMetadata
}

// MethodMetadata method metadata.
type MethodMetadata struct {
	// UpdateCommitment is update commitment key.
	UpdateCommitment string `json:"updateCommitment,omitempty"`
	// RecoveryCommitment is recovery commitment key.
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
	// Published is published key.
	Published bool `json:"published,omitempty"`
	// AnchorOrigin is anchor origin.
	AnchorOrigin string `json:"anchorOrigin,omitempty"`
	// UnpublishedOperations unpublished operations
	UnpublishedOperations []*Operations `json:"unpublishedOperations,omitempty"`
	// PublishedOperations published operations
	PublishedOperations []*Operations `json:"publishedOperations,omitempty"`
}

// Operations info.
type Operations struct {
	// OperationRequest is operation request.
	OperationRequest string `json:"operationRequest,omitempty"`
	// ProtocolVersion is protocol version.
	ProtocolVersion int `json:"protocolVersion,omitempty"`
	// TransactionNumber is transaction number.
	TransactionNumber int `json:"transactionNumber,omitempty"`
	// TransactionTime is transaction time.
	TransactionTime int64 `json:"transactionTime,omitempty"`
	// Type is type of operation.
	Type string `json:"type,omitempty"`
	// AnchorOrigin is anchor origin.
	AnchorOrigin string `json:"anchorOrigin,omitempty"`
	// CanonicalReference is canonical reference
	CanonicalReference string `json:"canonicalReference,omitempty"`
	// EquivalentReferences is equivalent references
	EquivalentReferences []string `json:"equivalentReferences,omitempty"`
}

// DocumentMetadata document metadata.
type DocumentMetadata struct {
	// Deactivated is deactivated flag key.
	Deactivated bool `json:"deactivated,omitempty"`
	// CanonicalID is canonical ID key.
	CanonicalID string `json:"canonicalId,omitempty"`
	// EquivalentID is equivalent ID array.
	EquivalentID []string `json:"equivalentId,omitempty"`
	// Method is used for method metadata within did document metadata.
	Method *MethodMetadata `json:"method,omitempty"`
}

type rawDocResolution struct {
	Context          interface{}     `json:"@context"`
	DIDDocument      json.RawMessage `json:"didDocument,omitempty"`
	DocumentMetadata json.RawMessage `json:"didDocumentMetadata,omitempty"`
}

// ParseDocumentResolution parse document resolution.
func ParseDocumentResolution(data []byte) (*DocResolution, error) {
	raw := &rawDocResolution{}

	if err := json.Unmarshal(data, raw); err != nil {
		return nil, err
	}

	if len(raw.DIDDocument) == 0 {
		return nil, ErrDIDDocumentNotExist
	}

	doc, err := ParseDocument(raw.DIDDocument)
	if err != nil {
		return nil, err
	}

	docMeta := &DocumentMetadata{}

	if len(raw.DocumentMetadata) != 0 {
		if err := json.Unmarshal(raw.DocumentMetadata, docMeta); err != nil {
			return nil, err
		}
	}

	context, _ := parseContext(raw.Context)

	return &DocResolution{Context: context, DIDDocument: doc, DocumentMetadata: docMeta}, nil
}

// Doc DID Document definition.
type Doc struct {
	Context              []string
	ID                   string
	VerificationMethod   []VerificationMethod
	Service              []Service
	Authentication       []Verification
	AssertionMethod      []Verification
	CapabilityDelegation []Verification
	CapabilityInvocation []Verification
	KeyAgreement         []Verification
	Created              *time.Time
	Updated              *time.Time
	Proof                []Proof
	processingMeta       processingMeta
}

// processingMeta include info how to process the doc.
type processingMeta struct {
	baseURI string
}

// VerificationMethod DID doc verification method.
// The value of the verification method is defined either as raw public key bytes (Value field) or as JSON Web Key.
// In the first case the Type field can hold additional information to understand the nature of the raw public key.
type VerificationMethod struct {
	ID         string
	Type       string
	Controller string

	Value []byte

	jsonWebKey  *jwk.JWK
	relativeURL bool
}

// NewVerificationMethodFromBytes creates a new VerificationMethod based on raw public key bytes.
func NewVerificationMethodFromBytes(id, keyType, controller string, value []byte) *VerificationMethod {
	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &VerificationMethod{
		ID:          id,
		Type:        keyType,
		Controller:  controller,
		Value:       value,
		relativeURL: relativeURL,
	}
}

// NewVerificationMethodFromJWK creates a new VerificationMethod based on JSON Web Key.
func NewVerificationMethodFromJWK(id, keyType, controller string, j *jwk.JWK) (*VerificationMethod, error) {
	pkBytes, err := j.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("convert JWK to public key bytes: %w", err)
	}

	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &VerificationMethod{
		ID:          id,
		Type:        keyType,
		Controller:  controller,
		Value:       pkBytes,
		jsonWebKey:  j,
		relativeURL: relativeURL,
	}, nil
}

// JSONWebKey returns JSON Web key if defined.
func (pk *VerificationMethod) JSONWebKey() *jwk.JWK {
	return pk.jsonWebKey
}

// Service DID doc service.
type Service struct {
	ID                       string                 `json:"id"`
	Type                     string                 `json:"type"`
	Priority                 uint                   `json:"priority,omitempty"`
	RecipientKeys            []string               `json:"recipientKeys,omitempty"`
	RoutingKeys              []string               `json:"routingKeys,omitempty"`
	ServiceEndpoint          string                 `json:"serviceEndpoint"`
	Accept                   []string               `json:"accept,omitempty"`
	Properties               map[string]interface{} `json:"properties,omitempty"`
	recipientKeysRelativeURL map[string]bool
	routingKeysRelativeURL   map[string]bool
	relativeURL              bool
}

// VerificationRelationship defines a verification relationship between DID subject and a verification method.
type VerificationRelationship int

const (
	// VerificationRelationshipGeneral is a special case of verification relationship: when a verification method
	// defined in Verification is not used by any Verification.
	VerificationRelationshipGeneral VerificationRelationship = iota

	// Authentication defines verification relationship.
	Authentication

	// AssertionMethod defines verification relationship.
	AssertionMethod

	// CapabilityDelegation defines verification relationship.
	CapabilityDelegation

	// CapabilityInvocation defines verification relationship.
	CapabilityInvocation

	// KeyAgreement defines verification relationship.
	KeyAgreement
)

// Verification authentication verification.
type Verification struct {
	VerificationMethod VerificationMethod
	Relationship       VerificationRelationship
	Embedded           bool
}

// NewEmbeddedVerification creates a new verification method with embedded verification method.
func NewEmbeddedVerification(vm *VerificationMethod, r VerificationRelationship) *Verification {
	return &Verification{
		VerificationMethod: *vm,
		Relationship:       r,
		Embedded:           true,
	}
}

// NewReferencedVerification creates a new verification method with referenced verification method.
func NewReferencedVerification(vm *VerificationMethod, r VerificationRelationship) *Verification {
	return &Verification{
		VerificationMethod: *vm,
		Relationship:       r,
	}
}

type rawDoc struct {
	Context              interface{}              `json:"@context,omitempty"`
	ID                   string                   `json:"id,omitempty"`
	VerificationMethod   []map[string]interface{} `json:"verificationMethod,omitempty"`
	PublicKey            []map[string]interface{} `json:"publicKey,omitempty"`
	Service              []map[string]interface{} `json:"service,omitempty"`
	Authentication       []interface{}            `json:"authentication,omitempty"`
	AssertionMethod      []interface{}            `json:"assertionMethod,omitempty"`
	CapabilityDelegation []interface{}            `json:"capabilityDelegation,omitempty"`
	CapabilityInvocation []interface{}            `json:"capabilityInvocation,omitempty"`
	KeyAgreement         []interface{}            `json:"keyAgreement,omitempty"`
	Created              *time.Time               `json:"created,omitempty"`
	Updated              *time.Time               `json:"updated,omitempty"`
	Proof                []interface{}            `json:"proof,omitempty"`
}

// Proof is cryptographic proof of the integrity of the DID Document.
type Proof struct {
	Type         string
	Created      *time.Time
	Creator      string
	ProofValue   []byte
	Domain       string
	Nonce        []byte
	ProofPurpose string
	relativeURL  bool
}

// UnmarshalJSON unmarshals a DID Document.
func (doc *Doc) UnmarshalJSON(data []byte) error {
	_doc, err := ParseDocument(data)
	if err != nil {
		return fmt.Errorf("failed to parse did doc: %w", err)
	}

	*doc = *_doc

	return nil
}

// ParseDocument creates an instance of DIDDocument by reading a JSON document from bytes.
func ParseDocument(data []byte) (*Doc, error) {
	raw := &rawDoc{}

	err := json.Unmarshal(data, &raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of did doc bytes bytes failed: %w", err)
	} else if raw == nil {
		return nil, errors.New("document payload is not provided")
	}

	// Interop: handle legacy did docs that incorrectly indicate they use the new format
	// aca-py issue: https://github.com/hyperledger/aries-cloudagent-python/issues/1048
	if doACAPYInterop && requiresLegacyHandling(raw) {
		raw.Context = []string{contextV011}
	} else {
		// validate did document
		err = validate(data, raw.schemaLoader())
		if err != nil {
			return nil, err
		}
	}

	doc := &Doc{
		ID:      raw.ID,
		Created: raw.Created,
		Updated: raw.Updated,
	}

	context, baseURI := parseContext(raw.Context)
	doc.Context = context
	doc.processingMeta = processingMeta{baseURI: baseURI}
	doc.Service = populateServices(raw.ID, baseURI, raw.Service)

	verificationMethod := raw.PublicKey
	if len(raw.VerificationMethod) != 0 {
		verificationMethod = raw.VerificationMethod
	}

	vm, err := populateVerificationMethod(context[0], doc.ID, baseURI, verificationMethod)
	if err != nil {
		return nil, fmt.Errorf("populate verification method failed: %w", err)
	}

	doc.VerificationMethod = vm

	err = populateVerificationRelationships(doc, raw)
	if err != nil {
		return nil, err
	}

	proofs, err := populateProofs(context[0], doc.ID, baseURI, raw.Proof)
	if err != nil {
		return nil, fmt.Errorf("populate proofs failed: %w", err)
	}

	doc.Proof = proofs

	return doc, nil
}

func requiresLegacyHandling(raw *rawDoc) bool {
	context, _ := parseContext(raw.Context)

	for _, ctx := range context {
		if ctx == ContextV1Old {
			// aca-py issue: https://github.com/hyperledger/aries-cloudagent-python/issues/1048
			//  old v1 context is (currently) only used by projects like aca-py that
			//  have not fully updated to latest did spec for aip2.0
			return true
		}
	}

	return false
}

func populateVerificationRelationships(doc *Doc, raw *rawDoc) error {
	authentications, err := populateVerification(doc, raw.Authentication, Authentication)
	if err != nil {
		return fmt.Errorf("populate authentications failed: %w", err)
	}

	doc.Authentication = authentications

	assertionMethods, err := populateVerification(doc, raw.AssertionMethod, AssertionMethod)
	if err != nil {
		return fmt.Errorf("populate assertion methods failed: %w", err)
	}

	doc.AssertionMethod = assertionMethods

	capabilityDelegations, err := populateVerification(doc, raw.CapabilityDelegation, CapabilityDelegation)
	if err != nil {
		return fmt.Errorf("populate capability delegations failed: %w", err)
	}

	doc.CapabilityDelegation = capabilityDelegations

	capabilityInvocations, err := populateVerification(doc, raw.CapabilityInvocation, CapabilityInvocation)
	if err != nil {
		return fmt.Errorf("populate capability invocations failed: %w", err)
	}

	doc.CapabilityInvocation = capabilityInvocations

	keyAgreements, err := populateVerification(doc, raw.KeyAgreement, KeyAgreement)
	if err != nil {
		return fmt.Errorf("populate key agreements failed: %w", err)
	}

	doc.KeyAgreement = keyAgreements

	return nil
}

func populateProofs(context, didID, baseURI string, rawProofs []interface{}) ([]Proof, error) {
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

		creator := stringEntry(emap[jsonldCreator])

		isRelative := false

		if strings.HasPrefix(creator, "#") {
			creator = resolveRelativeDIDURL(didID, baseURI, creator)
			isRelative = true
		}

		proof := Proof{
			Type:         stringEntry(emap[jsonldType]),
			Created:      &timeValue,
			Creator:      creator,
			ProofValue:   proofValue,
			ProofPurpose: stringEntry(emap[jsonldProofPurpose]),
			Domain:       stringEntry(emap[jsonldDomain]),
			Nonce:        nonce,
			relativeURL:  isRelative,
		}

		proofs = append(proofs, proof)
	}

	return proofs, nil
}

func populateServices(didID, baseURI string, rawServices []map[string]interface{}) []Service {
	services := make([]Service, 0, len(rawServices))

	for _, rawService := range rawServices {
		id := stringEntry(rawService[jsonldID])
		recipientKeys := stringArray(rawService[jsonldRecipientKeys])
		routingKeys := stringArray(rawService[jsonldRoutingKeys])

		var recipientKeysRelativeURL map[string]bool

		var routingKeysRelativeURL map[string]bool

		isRelative := false

		if strings.HasPrefix(id, "#") {
			id = resolveRelativeDIDURL(didID, baseURI, id)
			isRelative = true
		}

		if len(recipientKeys) != 0 {
			recipientKeys, recipientKeysRelativeURL = populateKeys(recipientKeys, didID, baseURI)
		}

		if len(routingKeys) != 0 {
			routingKeys, routingKeysRelativeURL = populateKeys(routingKeys, didID, baseURI)
		}

		service := Service{
			ID: id, Type: stringEntry(rawService[jsonldType]), relativeURL: isRelative,
			ServiceEndpoint: stringEntry(rawService[jsonldServicePoint]), RecipientKeys: recipientKeys,
			RoutingKeys: routingKeys, Priority: uintEntry(rawService[jsonldPriority]),
			recipientKeysRelativeURL: recipientKeysRelativeURL, routingKeysRelativeURL: routingKeysRelativeURL,
		}

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

func populateKeys(keys []string, didID, baseURI string) ([]string, map[string]bool) {
	values := make([]string, 0)
	keysRelativeURL := make(map[string]bool)

	for _, v := range keys {
		if strings.HasPrefix(v, "#") {
			id := resolveRelativeDIDURL(didID, baseURI, v)
			values = append(values, id)
			keysRelativeURL[id] = true

			continue
		}

		keysRelativeURL[v] = false

		values = append(values, v)
	}

	return values, keysRelativeURL
}

func populateVerification(doc *Doc, rawVerification []interface{},
	relationship VerificationRelationship) ([]Verification, error) {
	var vms []Verification

	for _, rawVerification := range rawVerification {
		v, err := getVerification(doc, rawVerification, relationship)
		if err != nil {
			return nil, err
		}

		vms = append(vms, v...)
	}

	return vms, nil
}

// getVerification gets verification from raw data.
func getVerification(doc *Doc, rawVerification interface{},
	relationship VerificationRelationship) ([]Verification, error) {
	// context, docID string
	vm := doc.VerificationMethod
	context := doc.Context[0]

	keyID, keyIDExist := rawVerification.(string)
	if keyIDExist {
		return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyID)
	}

	m, ok := rawVerification.(map[string]interface{})
	if !ok {
		return nil, errors.New("rawVerification is not map[string]interface{}")
	}

	if context == contextV011 {
		keyID, keyIDExist = m[jsonldPublicKey].(string)
		if keyIDExist {
			return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyID)
		}
	}

	if context == contextV12019 {
		keyIDs, keyIDsExist := m[jsonldPublicKey].([]interface{})
		if keyIDsExist {
			return getVerificationsByKeyID(doc.ID, doc.processingMeta.baseURI, vm, relationship, keyIDs...)
		}
	}

	pk, err := populateVerificationMethod(context, doc.ID, doc.processingMeta.baseURI, []map[string]interface{}{m})
	if err != nil {
		return nil, err
	}

	return []Verification{{VerificationMethod: pk[0], Relationship: relationship, Embedded: true}}, nil
}

// getVerificationsByKeyID get verification methods by key IDs.
func getVerificationsByKeyID(didID, baseURI string, vm []VerificationMethod, relationship VerificationRelationship,
	keyIDs ...interface{}) ([]Verification, error) {
	var vms []Verification

	for _, keyID := range keyIDs {
		keyExist := false

		if keyID == "" {
			continue
		}

		for _, v := range vm {
			if v.ID == keyID || v.ID == resolveRelativeDIDURL(didID, baseURI, keyID) {
				vms = append(vms, Verification{VerificationMethod: v, Relationship: relationship})
				keyExist = true

				break
			}
		}

		if !keyExist {
			return nil, fmt.Errorf("key %s does not exist in did doc verification method", keyID)
		}
	}

	return vms, nil
}

func resolveRelativeDIDURL(didID, baseURI string, keyID interface{}) string {
	id := baseURI

	if id == "" {
		id = didID
	}

	return id + keyID.(string)
}

func makeRelativeDIDURL(didURL, baseURI, didID string) string {
	id := baseURI

	if id == "" {
		id = didID
	}

	return strings.Replace(didURL, id, "", 1)
}

func populateVerificationMethod(context, didID, baseURI string,
	rawVM []map[string]interface{}) ([]VerificationMethod, error) {
	var verificationMethods []VerificationMethod

	for _, v := range rawVM {
		controllerKey := jsonldController

		if context == contextV011 {
			controllerKey = jsonldOwner
		}

		id := stringEntry(v[jsonldID])
		controller := stringEntry(v[controllerKey])

		isRelative := false

		if strings.HasPrefix(id, "#") {
			id = resolveRelativeDIDURL(didID, baseURI, id)
			split := strings.Split(id, "#")
			controller = split[0]
			isRelative = true
		}

		vm := VerificationMethod{
			ID: id, Type: stringEntry(v[jsonldType]),
			Controller:  controller,
			relativeURL: isRelative,
		}

		err := decodeVM(&vm, v)
		if err != nil {
			return nil, err
		}

		verificationMethods = append(verificationMethods, vm)
	}

	return verificationMethods, nil
}

func decodeVM(vm *VerificationMethod, rawPK map[string]interface{}) error {
	if stringEntry(rawPK[jsonldPublicKeyBase58]) != "" {
		vm.Value = base58.Decode(stringEntry(rawPK[jsonldPublicKeyBase58]))
		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyHex]) != "" {
		value, err := hex.DecodeString(stringEntry(rawPK[jsonldPublicKeyHex]))
		if err != nil {
			return fmt.Errorf("decode public key hex failed: %w", err)
		}

		vm.Value = value

		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyPem]) != "" {
		block, _ := pem.Decode([]byte(stringEntry(rawPK[jsonldPublicKeyPem])))
		if block == nil {
			return errors.New("failed to decode PEM block containing public key")
		}

		vm.Value = block.Bytes

		return nil
	}

	if jwkMap := mapEntry(rawPK[jsonldPublicKeyjwk]); jwkMap != nil {
		return decodeVMJwk(jwkMap, vm)
	}

	return errors.New("public key encoding not supported")
}

func decodeVMJwk(jwkMap map[string]interface{}, vm *VerificationMethod) error {
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return fmt.Errorf("failed to marshal '%s', cause: %w ", jsonldPublicKeyjwk, err)
	}

	if string(jwkBytes) == "{}" {
		vm.Value = []byte("")
		return nil
	}

	var j jwk.JWK

	err = json.Unmarshal(jwkBytes, &j)
	if err != nil {
		return fmt.Errorf("unmarshal JWK: %w", err)
	}

	pkBytes, err := j.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to decode public key from JWK: %w", err)
	}

	vm.Value = pkBytes
	vm.jsonWebKey = &j

	return nil
}

func parseContext(context interface{}) ([]string, string) {
	switch ctx := context.(type) {
	case []interface{}:
		var context []string

		var base string

		for _, v := range ctx {
			switch value := v.(type) {
			case string:
				context = append(context, value)
			case map[string]interface{}:
				baseValue, ok := value["@base"].(string)
				if ok {
					base = baseValue
				}
			}
		}

		return context, base
	case []string:
		return ctx, ""
	case interface{}:
		return []string{context.(string)}, ""
	}

	return []string{""}, ""
}

func (r *rawDoc) schemaLoader() gojsonschema.JSONLoader {
	context, _ := parseContext(r.Context)
	if len(context) == 0 {
		return schemaLoaderV1
	}

	switch context[0] {
	case contextV011:
		return schemaLoaderV011
	case contextV12019:
		return schemaLoaderV12019
	default:
		return schemaLoaderV1
	}
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

		errMsg += fmt.Sprintf("Document: %s\n", string(data))

		return errors.New(errMsg)
	}

	return nil
}

// stringEntry.
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}

	return entry.(string)
}

// uintEntry.
func uintEntry(entry interface{}) uint {
	if entry == nil {
		return 0
	}

	return uint(entry.(float64))
}

// stringArray.
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

func mapEntry(entry interface{}) map[string]interface{} {
	if entry == nil {
		return nil
	}

	result, ok := entry.(map[string]interface{})
	if !ok {
		return nil
	}

	return result
}

// JSONBytes converts document to json bytes.
func (docResolution *DocResolution) JSONBytes() ([]byte, error) {
	didBytes, err := docResolution.DIDDocument.JSONBytes()
	if err != nil {
		return nil, err
	}

	documentMetadataBytes, err := json.Marshal(docResolution.DocumentMetadata)
	if err != nil {
		return nil, err
	}

	raw := &rawDocResolution{
		Context:          docResolution.Context,
		DIDDocument:      didBytes,
		DocumentMetadata: documentMetadataBytes,
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON marshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

// JSONBytes converts document to json bytes.
func (doc *Doc) JSONBytes() ([]byte, error) {
	context := ContextV1

	if len(doc.Context) > 0 {
		context = doc.Context[0]
	}

	vm, err := populateRawVM(context, doc.ID, doc.processingMeta.baseURI, doc.VerificationMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Verification Method failed: %w", err)
	}

	auths, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID, doc.Authentication)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Authentication failed: %w", err)
	}

	assertionMethods, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of AssertionMethod failed: %w", err)
	}

	capabilityDelegations, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityDelegation failed: %w", err)
	}

	capabilityInvocations, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityInvocation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityInvocation failed: %w", err)
	}

	keyAgreements, err := populateRawVerification(context, doc.processingMeta.baseURI, doc.ID, doc.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of KeyAgreement failed: %w", err)
	}

	raw := &rawDoc{
		Context: doc.Context, ID: doc.ID, VerificationMethod: vm,
		Authentication: auths, AssertionMethod: assertionMethods, CapabilityDelegation: capabilityDelegations,
		CapabilityInvocation: capabilityInvocations, KeyAgreement: keyAgreements,
		Service: populateRawServices(doc.Service, doc.ID, doc.processingMeta.baseURI), Created: doc.Created,
		Proof: populateRawProofs(context, doc.ID, doc.processingMeta.baseURI, doc.Proof), Updated: doc.Updated,
	}

	if doc.processingMeta.baseURI != "" {
		raw.Context = contextWithBase(doc)
	}

	byteDoc, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of document failed: %w", err)
	}

	return byteDoc, nil
}

func contextWithBase(doc *Doc) []interface{} {
	baseObject := make(map[string]interface{})
	baseObject["@base"] = doc.processingMeta.baseURI

	m := make([]interface{}, 0)

	for _, v := range doc.Context {
		m = append(m, v)
	}

	m = append(m, baseObject)

	return m
}

// MarshalJSON marshals the DID Document.
func (doc *Doc) MarshalJSON() ([]byte, error) {
	return doc.JSONBytes()
}

// VerifyProof verifies document proofs.
func (doc *Doc) VerifyProof(suites []verifier.SignatureSuite, jsonldOpts ...jsonld.ProcessorOpts) error {
	if len(doc.Proof) == 0 {
		return ErrProofNotFound
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		return err
	}

	v, err := verifier.New(&didKeyResolver{doc.VerificationMethod}, suites...)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	return v.Verify(docBytes, jsonldOpts...)
}

// VerificationMethods returns verification methods of DID Doc of certain relationship.
// If customVerificationRelationships is empty, all verification methods are returned.
// Public keys which are not referred by any verification method are put into special VerificationRelationshipGeneral
// relationship category.
// nolint:gocyclo
func (doc *Doc) VerificationMethods(customVerificationRelationships ...VerificationRelationship) map[VerificationRelationship][]Verification { //nolint:lll
	all := len(customVerificationRelationships) == 0

	includeRelationship := func(relationship VerificationRelationship) bool {
		if all {
			return true
		}

		for _, r := range customVerificationRelationships {
			if r == relationship {
				return true
			}
		}

		return false
	}

	verificationMethods := make(map[VerificationRelationship][]Verification)

	if len(doc.Authentication) > 0 && includeRelationship(Authentication) {
		verificationMethods[Authentication] = doc.Authentication
	}

	if len(doc.AssertionMethod) > 0 && includeRelationship(AssertionMethod) {
		verificationMethods[AssertionMethod] = doc.AssertionMethod
	}

	if len(doc.CapabilityDelegation) > 0 && includeRelationship(CapabilityDelegation) {
		verificationMethods[CapabilityDelegation] = doc.CapabilityDelegation
	}

	if len(doc.CapabilityInvocation) > 0 && includeRelationship(CapabilityInvocation) {
		verificationMethods[CapabilityInvocation] = doc.CapabilityInvocation
	}

	if len(doc.KeyAgreement) > 0 && includeRelationship(KeyAgreement) {
		verificationMethods[KeyAgreement] = doc.KeyAgreement
	}

	if len(doc.VerificationMethod) > 0 && includeRelationship(VerificationRelationshipGeneral) {
		generalVerificationMethods := make([]Verification, len(doc.VerificationMethod))

		for i := range doc.VerificationMethod {
			generalVerificationMethods[i] = Verification{
				VerificationMethod: doc.VerificationMethod[i],
				Relationship:       VerificationRelationshipGeneral,
				Embedded:           true,
			}
		}

		verificationMethods[VerificationRelationshipGeneral] = generalVerificationMethods
	}

	return verificationMethods
}

// ErrProofNotFound is returned when proof is not found.
var ErrProofNotFound = errors.New("proof not found")

// didKeyResolver implements public key resolution for DID public keys.
type didKeyResolver struct {
	PubKeys []VerificationMethod
}

func (r *didKeyResolver) Resolve(id string) (*verifier.PublicKey, error) {
	for _, key := range r.PubKeys {
		if key.ID == id {
			return &verifier.PublicKey{
				Type:  key.Type,
				Value: key.Value,
				JWK:   key.jsonWebKey,
			}, nil
		}
	}

	return nil, ErrKeyNotFound
}

// ErrKeyNotFound is returned when key is not found.
var ErrKeyNotFound = errors.New("key not found")

func populateRawServices(services []Service, didID, baseURI string) []map[string]interface{} {
	var rawServices []map[string]interface{}

	for i := range services {
		rawService := make(map[string]interface{})

		for k, v := range services[i].Properties {
			rawService[k] = v
		}

		routingKeys := make([]string, 0)

		for _, v := range services[i].RoutingKeys {
			if services[i].routingKeysRelativeURL[v] {
				routingKeys = append(routingKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}

			routingKeys = append(routingKeys, v)
		}

		recipientKeys := make([]string, 0)

		for _, v := range services[i].RecipientKeys {
			if services[i].recipientKeysRelativeURL[v] {
				recipientKeys = append(recipientKeys, makeRelativeDIDURL(v, baseURI, didID))
				continue
			}

			recipientKeys = append(recipientKeys, v)
		}

		rawService[jsonldID] = services[i].ID
		if services[i].relativeURL {
			rawService[jsonldID] = makeRelativeDIDURL(services[i].ID, baseURI, didID)
		}

		rawService[jsonldType] = services[i].Type
		rawService[jsonldServicePoint] = services[i].ServiceEndpoint
		rawService[jsonldPriority] = services[i].Priority

		if len(recipientKeys) > 0 {
			rawService[jsonldRecipientKeys] = recipientKeys
		}

		if len(routingKeys) > 0 {
			rawService[jsonldRoutingKeys] = routingKeys
		}

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}

func populateRawVM(context, didID, baseURI string, pks []VerificationMethod) ([]map[string]interface{}, error) {
	var rawVM []map[string]interface{}

	for i := range pks {
		vm, err := populateRawVerificationMethod(context, didID, baseURI, &pks[i])
		if err != nil {
			return nil, err
		}

		rawVM = append(rawVM, vm)
	}

	return rawVM, nil
}

func populateRawVerificationMethod(context, didID, baseURI string,
	vm *VerificationMethod) (map[string]interface{}, error) {
	rawVM := make(map[string]interface{})
	rawVM[jsonldID] = vm.ID

	if vm.relativeURL {
		rawVM[jsonldID] = makeRelativeDIDURL(vm.ID, baseURI, didID)
	}

	rawVM[jsonldType] = vm.Type

	if context == contextV011 {
		rawVM[jsonldOwner] = vm.Controller
	} else {
		rawVM[jsonldController] = vm.Controller
		if vm.relativeURL {
			rawVM[jsonldController] = ""
		}
	}

	if vm.jsonWebKey != nil {
		jwkBytes, err := json.Marshal(vm.jsonWebKey)
		if err != nil {
			return nil, err
		}

		rawVM[jsonldPublicKeyjwk] = json.RawMessage(jwkBytes)
	} else if vm.Value != nil {
		rawVM[jsonldPublicKeyBase58] = base58.Encode(vm.Value)
	}

	return rawVM, nil
}

func populateRawVerification(context, baseURI, didID string, verifications []Verification) ([]interface{}, error) {
	var rawVerifications []interface{}

	for _, v := range verifications {
		if v.Embedded {
			vm, err := populateRawVerificationMethod(context, didID, baseURI, &v.VerificationMethod)
			if err != nil {
				return nil, err
			}

			rawVerifications = append(rawVerifications, vm)
		} else {
			if v.VerificationMethod.relativeURL {
				rawVerifications = append(rawVerifications,
					makeRelativeDIDURL(v.VerificationMethod.ID, baseURI, didID))
			} else {
				rawVerifications = append(rawVerifications, v.VerificationMethod.ID)
			}
		}
	}

	return rawVerifications, nil
}

func populateRawProofs(context, didID, baseURI string, proofs []Proof) []interface{} {
	rawProofs := make([]interface{}, 0, len(proofs))

	k := jsonldProofValue

	if context == contextV011 {
		k = jsonldSignatureValue
	}

	for _, p := range proofs {
		creator := p.Creator
		if p.relativeURL {
			creator = makeRelativeDIDURL(p.Creator, baseURI, didID)
		}

		rawProofs = append(rawProofs, map[string]interface{}{
			jsonldType:         p.Type,
			jsonldCreated:      p.Created,
			jsonldCreator:      creator,
			k:                  base64.RawURLEncoding.EncodeToString(p.ProofValue),
			jsonldDomain:       p.Domain,
			jsonldNonce:        base64.RawURLEncoding.EncodeToString(p.Nonce),
			jsonldProofPurpose: p.ProofPurpose,
		})
	}

	return rawProofs
}

// DocOption provides options to build DID Doc.
type DocOption func(opts *Doc)

// WithVerificationMethod DID doc VerificationMethod.
func WithVerificationMethod(pubKey []VerificationMethod) DocOption {
	return func(opts *Doc) {
		opts.VerificationMethod = pubKey
	}
}

// WithAuthentication sets the verification methods for authentication: https://w3c.github.io/did-core/#authentication.
func WithAuthentication(auth []Verification) DocOption {
	return func(opts *Doc) {
		opts.Authentication = auth
	}
}

// WithAssertion sets the verification methods for assertion: https://w3c.github.io/did-core/#assertion.
func WithAssertion(assertion []Verification) DocOption {
	return func(opts *Doc) {
		opts.AssertionMethod = assertion
	}
}

// WithKeyAgreement sets the verification methods for KeyAgreement: https://w3c.github.io/did-core/#key-agreement.
func WithKeyAgreement(keyAgreement []Verification) DocOption {
	return func(opts *Doc) {
		opts.KeyAgreement = keyAgreement
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
	doc.Context = []string{ContextV1}

	for _, opt := range opts {
		opt(doc)
	}

	return doc
}
