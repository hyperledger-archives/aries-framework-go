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
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/piprate/json-gold/ld"
	"github.com/xeipuuv/gojsonschema"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

const (
	// Context of the DID document.
	Context             = "https://w3id.org/did/v1"
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

// Doc DID Document definition.
type Doc struct {
	Context              []string
	ID                   string
	PublicKey            []PublicKey
	Service              []Service
	Authentication       []VerificationMethod
	AssertionMethod      []VerificationMethod
	CapabilityDelegation []VerificationMethod
	CapabilityInvocation []VerificationMethod
	KeyAgreement         []VerificationMethod
	Created              *time.Time
	Updated              *time.Time
	Proof                []Proof
	processingMeta       processingMeta
}

// processingMeta include info how to process the doc.
type processingMeta struct {
	baseURI string
}

// PublicKey DID doc public key.
// The value of the public key is defined either as raw public key bytes (Value field) or as JSON Web Key.
// In the first case the Type field can hold additional information to understand the nature of the raw public key.
type PublicKey struct {
	ID         string
	Type       string
	Controller string

	Value []byte

	jsonWebKey  *jose.JWK
	relativeURL bool
}

// NewPublicKeyFromBytes creates a new PublicKey based on raw public key bytes.
func NewPublicKeyFromBytes(id, kType, controller string, value []byte) *PublicKey {
	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &PublicKey{
		ID:          id,
		Type:        kType,
		Controller:  controller,
		Value:       value,
		relativeURL: relativeURL,
	}
}

// NewPublicKeyFromJWK creates a new PublicKey based on JSON Web Key.
func NewPublicKeyFromJWK(id, kType, controller string, jwk *jose.JWK) (*PublicKey, error) {
	pkBytes, err := jwk.PublicKeyBytes()
	if err != nil {
		return nil, fmt.Errorf("convert JWK to public key bytes: %w", err)
	}

	relativeURL := false
	if strings.HasPrefix(id, "#") {
		relativeURL = true
	}

	return &PublicKey{
		ID:          id,
		Type:        kType,
		Controller:  controller,
		Value:       pkBytes,
		jsonWebKey:  jwk,
		relativeURL: relativeURL,
	}, nil
}

// JSONWebKey returns JSON Web key if defined.
func (pk *PublicKey) JSONWebKey() *jose.JWK {
	return pk.jsonWebKey
}

// Service DID doc service.
type Service struct {
	ID                       string
	Type                     string
	Priority                 uint
	RecipientKeys            []string
	RoutingKeys              []string
	ServiceEndpoint          string
	Properties               map[string]interface{}
	recipientKeysRelativeURL map[string]bool
	routingKeysRelativeURL   map[string]bool
	relativeURL              bool
}

// VerificationRelationship defines a verification relationship between DID subject and a verification method.
type VerificationRelationship int

const (
	// VerificationRelationshipGeneral is a special case of verification relationship: when a public key
	// defined in PublicKey is not used by any VerificationMethod.
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

// VerificationMethod authentication verification method.
type VerificationMethod struct {
	PublicKey    PublicKey
	Relationship VerificationRelationship
	Embedded     bool
}

// NewEmbeddedVerificationMethod creates a new verification method with embedded public key.
func NewEmbeddedVerificationMethod(pk *PublicKey, r VerificationRelationship) *VerificationMethod {
	return &VerificationMethod{
		PublicKey:    *pk,
		Relationship: r,
		Embedded:     true,
	}
}

// NewReferencedVerificationMethod creates a new verification method with referenced public key.
func NewReferencedVerificationMethod(pk *PublicKey, r VerificationRelationship) *VerificationMethod { //nolint:lll
	return &VerificationMethod{
		PublicKey:    *pk,
		Relationship: r,
	}
}

type rawDoc struct {
	Context              interface{}              `json:"@context,omitempty"`
	ID                   string                   `json:"id,omitempty"`
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

// ParseDocument creates an instance of DIDDocument by reading a JSON document from bytes.
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

	doc := &Doc{
		ID:      raw.ID,
		Created: raw.Created,
		Updated: raw.Updated,
	}

	context, baseURI := raw.ParseContext()
	doc.Context = context
	doc.processingMeta = processingMeta{baseURI: baseURI}
	doc.Service = populateServices(raw.ID, baseURI, raw.Service)

	publicKeys, err := populatePublicKeys(context[0], doc.ID, baseURI, raw.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("populate public keys failed: %w", err)
	}

	doc.PublicKey = publicKeys

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

func populateVerificationRelationships(doc *Doc, raw *rawDoc) error {
	authentications, err := populateVerificationMethods(doc, raw.Authentication, Authentication)
	if err != nil {
		return fmt.Errorf("populate authentications failed: %w", err)
	}

	doc.Authentication = authentications

	assertionMethods, err := populateVerificationMethods(doc, raw.AssertionMethod, AssertionMethod)
	if err != nil {
		return fmt.Errorf("populate assertion methods failed: %w", err)
	}

	doc.AssertionMethod = assertionMethods

	capabilityDelegations, err := populateVerificationMethods(doc, raw.CapabilityDelegation, CapabilityDelegation)
	if err != nil {
		return fmt.Errorf("populate capability delegations failed: %w", err)
	}

	doc.CapabilityDelegation = capabilityDelegations

	capabilityInvocations, err := populateVerificationMethods(doc, raw.CapabilityInvocation, CapabilityInvocation)
	if err != nil {
		return fmt.Errorf("populate capability invocations failed: %w", err)
	}

	doc.CapabilityInvocation = capabilityInvocations

	keyAgreements, err := populateVerificationMethods(doc, raw.KeyAgreement, KeyAgreement)
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

func populateVerificationMethods(doc *Doc, rawVerificationMethods []interface{},
	relationship VerificationRelationship) ([]VerificationMethod, error) {
	var vms []VerificationMethod

	for _, rawVerificationMethod := range rawVerificationMethods {
		v, err := getVerificationMethods(doc, rawVerificationMethod, relationship)
		if err != nil {
			return nil, err
		}

		vms = append(vms, v...)
	}

	return vms, nil
}

// getVerificationMethods gets verification methods from raw data.
func getVerificationMethods(doc *Doc, rawVerificationMethod interface{},
	relationship VerificationRelationship) ([]VerificationMethod, error) {
	// context, docID string
	pks := doc.PublicKey
	context := doc.Context[0]

	keyID, keyIDExist := rawVerificationMethod.(string)
	if keyIDExist {
		return getVerificationMethodsByKeyID(doc.ID, doc.processingMeta.baseURI, pks, relationship, keyID)
	}

	m, ok := rawVerificationMethod.(map[string]interface{})
	if !ok {
		return nil, errors.New("rawVerificationMethod is not map[string]interface{}")
	}

	if context == contextV011 {
		keyID, keyIDExist = m[jsonldPublicKey].(string)
		if keyIDExist {
			return getVerificationMethodsByKeyID(doc.ID, doc.processingMeta.baseURI, pks, relationship, keyID)
		}
	}

	if context == contextV12019 {
		keyIDs, keyIDsExist := m[jsonldPublicKey].([]interface{})
		if keyIDsExist {
			return getVerificationMethodsByKeyID(doc.ID, doc.processingMeta.baseURI, pks, relationship, keyIDs...)
		}
	}

	pk, err := populatePublicKeys(context, doc.ID, doc.processingMeta.baseURI, []map[string]interface{}{m})
	if err != nil {
		return nil, err
	}

	return []VerificationMethod{{PublicKey: pk[0], Relationship: relationship, Embedded: true}}, nil
}

// getVerificationMethodsByKeyID get verification methods by key IDs.
func getVerificationMethodsByKeyID(didID, baseURI string, pks []PublicKey, relationship VerificationRelationship,
	keyIDs ...interface{}) ([]VerificationMethod, error) {
	var vms []VerificationMethod

	for _, keyID := range keyIDs {
		keyExist := false

		if keyID == "" {
			continue
		}

		for _, pk := range pks {
			if pk.ID == keyID || pk.ID == resolveRelativeDIDURL(didID, baseURI, keyID) {
				vms = append(vms, VerificationMethod{PublicKey: pk, Relationship: relationship})
				keyExist = true

				break
			}
		}

		if !keyExist {
			return nil, fmt.Errorf("key %s not exist in did doc public key", keyID)
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

func populatePublicKeys(context, didID, baseURI string, rawPKs []map[string]interface{}) ([]PublicKey, error) {
	var publicKeys []PublicKey

	for _, rawPK := range rawPKs {
		controllerKey := jsonldController

		if context == contextV011 {
			controllerKey = jsonldOwner
		}

		id := stringEntry(rawPK[jsonldID])
		controller := stringEntry(rawPK[controllerKey])

		isRelative := false

		if strings.HasPrefix(id, "#") {
			id = resolveRelativeDIDURL(didID, baseURI, id)
			split := strings.Split(id, "#")
			controller = split[0]
			isRelative = true
		}

		publicKey := PublicKey{
			ID: id, Type: stringEntry(rawPK[jsonldType]),
			Controller:  controller,
			relativeURL: isRelative,
		}

		err := decodePK(&publicKey, rawPK)
		if err != nil {
			return nil, err
		}

		publicKeys = append(publicKeys, publicKey)
	}

	return publicKeys, nil
}

func decodePK(publicKey *PublicKey, rawPK map[string]interface{}) error {
	if stringEntry(rawPK[jsonldPublicKeyBase58]) != "" {
		publicKey.Value = base58.Decode(stringEntry(rawPK[jsonldPublicKeyBase58]))
		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyHex]) != "" {
		value, err := hex.DecodeString(stringEntry(rawPK[jsonldPublicKeyHex]))
		if err != nil {
			return fmt.Errorf("decode public key hex failed: %w", err)
		}

		publicKey.Value = value

		return nil
	}

	if stringEntry(rawPK[jsonldPublicKeyPem]) != "" {
		block, _ := pem.Decode([]byte(stringEntry(rawPK[jsonldPublicKeyPem])))
		if block == nil {
			return errors.New("failed to decode PEM block containing public key")
		}

		publicKey.Value = block.Bytes

		return nil
	}

	if jwkMap := mapEntry(rawPK[jsonldPublicKeyjwk]); jwkMap != nil {
		return decodePublicKeyJwk(jwkMap, publicKey)
	}

	return errors.New("public key encoding not supported")
}

func decodePublicKeyJwk(jwkMap map[string]interface{}, publicKey *PublicKey) error {
	jwkBytes, err := json.Marshal(jwkMap)
	if err != nil {
		return fmt.Errorf("failed to marshal '%s', cause: %w ", jsonldPublicKeyjwk, err)
	}

	if string(jwkBytes) == "{}" {
		publicKey.Value = []byte("")
		return nil
	}

	var jwk jose.JWK

	err = json.Unmarshal(jwkBytes, &jwk)
	if err != nil {
		return fmt.Errorf("unmarshal JWK: %w", err)
	}

	pkBytes, err := jwk.PublicKeyBytes()
	if err != nil {
		return fmt.Errorf("failed to decode public key from JWK: %w", err)
	}

	publicKey.Value = pkBytes
	publicKey.jsonWebKey = &jwk

	return nil
}

func (r *rawDoc) ParseContext() ([]string, string) {
	switch ctx := r.Context.(type) {
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
		return []string{r.Context.(string)}, ""
	}

	return []string{""}, ""
}

func (r *rawDoc) schemaLoader() gojsonschema.JSONLoader {
	context, _ := r.ParseContext()
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
func (doc *Doc) JSONBytes() ([]byte, error) {
	context := Context

	if len(doc.Context) > 0 {
		context = doc.Context[0]
	}

	publicKeys, err := populateRawPublicKeys(context, doc.ID, doc.processingMeta.baseURI, doc.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Public Key failed: %w", err)
	}

	auths, err := populateRawVerificationMethods(context, doc.processingMeta.baseURI, doc.ID, doc.Authentication)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of Authentication failed: %w", err)
	}

	assertionMethods, err := populateRawVerificationMethods(context, doc.processingMeta.baseURI, doc.ID,
		doc.AssertionMethod)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of AssertionMethod failed: %w", err)
	}

	capabilityDelegations, err := populateRawVerificationMethods(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityDelegation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityDelegation failed: %w", err)
	}

	capabilityInvocations, err := populateRawVerificationMethods(context, doc.processingMeta.baseURI, doc.ID,
		doc.CapabilityInvocation)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of CapabilityInvocation failed: %w", err)
	}

	keyAgreements, err := populateRawVerificationMethods(context, doc.processingMeta.baseURI, doc.ID, doc.KeyAgreement)
	if err != nil {
		return nil, fmt.Errorf("JSON unmarshalling of KeyAgreement failed: %w", err)
	}

	raw := &rawDoc{
		Context: doc.Context, ID: doc.ID, PublicKey: publicKeys,
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

// VerifyProof verifies document proofs.
func (doc *Doc) VerifyProof(suites []verifier.SignatureSuite, jsonldOpts ...jsonld.ProcessorOpts) error {
	if len(doc.Proof) == 0 {
		return ErrProofNotFound
	}

	docBytes, err := doc.JSONBytes()
	if err != nil {
		return err
	}

	v, err := verifier.New(&didKeyResolver{doc.PublicKey}, suites...)
	if err != nil {
		return fmt.Errorf("create verifier: %w", err)
	}

	defaultDocumentLoaderOpt := []jsonld.ProcessorOpts{jsonld.WithDocumentLoader(CachingJSONLDLoader())}

	return v.Verify(docBytes, append(defaultDocumentLoaderOpt, jsonldOpts...)...)
}

// VerificationMethods returns verification methods of DID Doc of certain relationship.
// If customVerificationRelationships is empty, all verification methods are returned.
// Public keys which are not referred by any verification method are put into special VerificationRelationshipGeneral
// relationship category.
// nolint:gocyclo
func (doc *Doc) VerificationMethods(customVerificationRelationships ...VerificationRelationship) map[VerificationRelationship][]VerificationMethod { //nolint:lll
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

	verificationMethods := make(map[VerificationRelationship][]VerificationMethod)

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

	if len(doc.PublicKey) > 0 && includeRelationship(VerificationRelationshipGeneral) {
		generalVerificationMethods := make([]VerificationMethod, len(doc.PublicKey))

		for i := range doc.PublicKey {
			generalVerificationMethods[i] = VerificationMethod{
				PublicKey:    doc.PublicKey[i],
				Relationship: VerificationRelationshipGeneral,
				Embedded:     true,
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
	PubKeys []PublicKey
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
			if services[i].routingKeysRelativeURL[v] {
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
		rawService[jsonldRecipientKeys] = recipientKeys
		rawService[jsonldRoutingKeys] = routingKeys
		rawService[jsonldPriority] = services[i].Priority

		rawServices = append(rawServices, rawService)
	}

	return rawServices
}

func populateRawPublicKeys(context, didID, baseURI string, pks []PublicKey) ([]map[string]interface{}, error) {
	var rawPKs []map[string]interface{}

	for i := range pks {
		publicKey, err := populateRawPublicKey(context, didID, baseURI, &pks[i])
		if err != nil {
			return nil, err
		}

		rawPKs = append(rawPKs, publicKey)
	}

	return rawPKs, nil
}

func populateRawPublicKey(context, didID, baseURI string, pk *PublicKey) (map[string]interface{}, error) {
	rawPK := make(map[string]interface{})
	rawPK[jsonldID] = pk.ID

	if pk.relativeURL {
		rawPK[jsonldID] = makeRelativeDIDURL(pk.ID, baseURI, didID)
	}

	rawPK[jsonldType] = pk.Type

	if context == contextV011 {
		rawPK[jsonldOwner] = pk.Controller
	} else {
		rawPK[jsonldController] = pk.Controller
		if pk.relativeURL {
			rawPK[jsonldController] = ""
		}
	}

	if pk.jsonWebKey != nil {
		jwkBytes, err := json.Marshal(pk.jsonWebKey)
		if err != nil {
			return nil, err
		}

		rawPK[jsonldPublicKeyjwk] = json.RawMessage(jwkBytes)
	} else if pk.Value != nil {
		rawPK[jsonldPublicKeyBase58] = base58.Encode(pk.Value)
	}

	return rawPK, nil
}

func populateRawVerificationMethods(context, baseURI, didID string, vms []VerificationMethod) ([]interface{}, error) {
	var rawVerificationMethods []interface{}

	for _, vm := range vms {
		if vm.Embedded {
			publicKey, err := populateRawPublicKey(context, didID, baseURI, &vm.PublicKey)
			if err != nil {
				return nil, err
			}

			rawVerificationMethods = append(rawVerificationMethods, publicKey)
		} else {
			if vm.PublicKey.relativeURL {
				rawVerificationMethods = append(rawVerificationMethods, makeRelativeDIDURL(vm.PublicKey.ID, baseURI, didID))
			} else {
				rawVerificationMethods = append(rawVerificationMethods, vm.PublicKey.ID)
			}
		}
	}

	return rawVerificationMethods, nil
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

// WithPublicKey DID doc PublicKey.
func WithPublicKey(pubKey []PublicKey) DocOption {
	return func(opts *Doc) {
		opts.PublicKey = pubKey
	}
}

// WithAuthentication sets the verification methods for authentication: https://w3c.github.io/did-core/#authentication.
func WithAuthentication(auth []VerificationMethod) DocOption {
	return func(opts *Doc) {
		opts.Authentication = auth
	}
}

// WithAssertion sets the verification methods for assertion: https://w3c.github.io/did-core/#assertionmethod.
func WithAssertion(assertion []VerificationMethod) DocOption {
	return func(opts *Doc) {
		opts.AssertionMethod = assertion
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

// CachingJSONLDLoader creates JSON-LD CachingDocumentLoader with preloaded base JSON-LD DID and security contexts.
func CachingJSONLDLoader() ld.DocumentLoader {
	loader := ld.NewCachingDocumentLoader(ld.NewRFC7324CachingDocumentLoader(&http.Client{}))

	cacheContext := func(source, url string) {
		reader, _ := ld.DocumentFromReader(strings.NewReader(source)) //nolint:errcheck
		loader.AddDocument(url, reader)
	}

	cacheContext(didV011Context, "https://w3id.org/did/v0.11")
	cacheContext(didV1Context, "https://w3id.org/did/v1")
	cacheContext(didV1Context, "https://www.w3.org/ns/did/v1")
	cacheContext(securityV1Context, "https://w3id.org/security/v1")
	cacheContext(securityV2Context, "https://w3id.org/security/v2")

	return loader
}
