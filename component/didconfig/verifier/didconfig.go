/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifier

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/component/log"
	diddoc "github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/verifiable"
	"github.com/hyperledger/aries-framework-go/component/vdr"
	"github.com/hyperledger/aries-framework-go/component/vdr/key"
	vdrapi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

var logger = log.New("aries-framework/doc/didconfig")

const (
	// ContextV0 is did configuration context version 0.
	ContextV0 = "https://identity.foundation/.well-known/contexts/did-configuration-v0.0.jsonld"

	// ContextV1 is did configuration context version 1.
	ContextV1 = "https://identity.foundation/.well-known/did-configuration/v1"

	domainLinkageCredentialType = "DomainLinkageCredential"

	contextProperty    = "@context"
	linkedDIDsProperty = "linked_dids"
)

type didResolver interface {
	Resolve(did string, opts ...vdrapi.DIDMethodOption) (*diddoc.DocResolution, error)
}

// didConfigOpts holds options for the DID Configuration decoding.
type didConfigOpts struct {
	jsonldDocumentLoader jsonld.DocumentLoader
	didResolver          didResolver
}

// DIDConfigurationOpt is the DID Configuration decoding option.
type DIDConfigurationOpt func(opts *didConfigOpts)

// WithJSONLDDocumentLoader defines a JSON-LD document loader.
func WithJSONLDDocumentLoader(documentLoader jsonld.DocumentLoader) DIDConfigurationOpt {
	return func(opts *didConfigOpts) {
		opts.jsonldDocumentLoader = documentLoader
	}
}

// WithVDRegistry defines a vdr service.
func WithVDRegistry(didResolver didResolver) DIDConfigurationOpt {
	return func(opts *didConfigOpts) {
		opts.didResolver = didResolver
	}
}

type rawDoc struct {
	Context    string        `json:"@context,omitempty"`
	LinkedDIDs []interface{} `json:"linked_dids,omitempty"`
}

// VerifyDIDAndDomain will verify that there is valid domain linkage credential in did configuration
// for specified did and domain.
func VerifyDIDAndDomain(didConfig []byte, did, domain string, opts ...DIDConfigurationOpt) error {
	// apply options
	didCfgOpts := getDIDConfigurationOpts(opts)

	// verify required and allowed properties in did configuration
	err := verifyDidConfigurationProperties(didConfig)
	if err != nil {
		return err
	}

	raw := rawDoc{}

	err = json.Unmarshal(didConfig, &raw)
	if err != nil {
		return fmt.Errorf("JSON unmarshalling of DID configuration bytes failed: %w", err)
	}

	credOpts := getParseCredentialOptions(true, didCfgOpts)

	credentials, err := getCredentials(raw.LinkedDIDs, did, domain, credOpts...)
	if err != nil {
		return err
	}

	logger.Debugf("found %d domain linkage credential(s) for DID[%s] and domain[%s]", len(credentials), did, domain)

	for _, credBytes := range credentials {
		credOpts := getParseCredentialOptions(false, didCfgOpts)

		// this time we are parsing credential with proof check so DID will be resolved
		// and public key from did will be used to verify proof
		_, err := verifiable.ParseCredential(credBytes, credOpts...)
		if err == nil {
			// we found domain linkage credential with valid proof so all good
			return nil
		}

		// failed to verify credential proof - log info and continue to next one
		logger.Warnf("skipping domain linkage credential for DID[%s] and domain[%s] due to error: %s",
			did, domain, err.Error())
	}

	return fmt.Errorf("domain linkage credential(s) with valid proof not found")
}

func getDIDConfigurationOpts(opts []DIDConfigurationOpt) *didConfigOpts {
	didCfgOpts := &didConfigOpts{
		jsonldDocumentLoader: jsonld.NewDefaultDocumentLoader(http.DefaultClient),
		didResolver:          vdr.New(vdr.WithVDR(key.New())),
	}

	for _, opt := range opts {
		opt(didCfgOpts)
	}

	return didCfgOpts
}

func verifyDidConfigurationProperties(data []byte) error {
	requiredProperties := []string{contextProperty, linkedDIDsProperty}
	allowedProperties := []string{contextProperty, linkedDIDsProperty}

	var didCfgMap map[string]interface{}

	err := json.Unmarshal(data, &didCfgMap)
	if err != nil {
		return fmt.Errorf("JSON unmarshalling of DID configuration bytes failed: %w", err)
	} else if didCfgMap == nil {
		return errors.New("DID configuration payload is not provided")
	}

	if err := verifyRequiredProperties(didCfgMap, requiredProperties); err != nil {
		return fmt.Errorf("did configuration: %w ", err)
	}

	return verifyAllowedProperties(didCfgMap, allowedProperties)
}

func verifyRequiredProperties(values map[string]interface{}, requiredProperties []string) error {
	for _, key := range requiredProperties {
		if _, ok := values[key]; !ok {
			return fmt.Errorf("property '%s' is required", key)
		}
	}

	return nil
}

func verifyAllowedProperties(values map[string]interface{}, allowedProperty []string) error {
	for key := range values {
		if !contains(key, allowedProperty) {
			return fmt.Errorf("property '%s' is not allowed", key)
		}
	}

	return nil
}

func isValidDomainLinkageCredential(vc *verifiable.Credential, did, origin string) error {
	// validate JWT format if credential has been parsed from JWT format
	// https://identity.foundation/.well-known/resources/did-configuration/#json-web-token-proof-format
	if vc.JWT != "" {
		return validateJWT(vc, did, origin)
	}

	// validate domain linkage credential rules:
	// https://identity.foundation/.well-known/resources/did-configuration/#domain-linkage-credential
	return validateDomainLinkageCredential(vc, did, origin)
}

func validateDomainLinkageCredential(vc *verifiable.Credential, did, origin string) error {
	if !contains(domainLinkageCredentialType, vc.Types) {
		return fmt.Errorf("credential is not of %s type", domainLinkageCredentialType)
	}

	if vc.ID != "" {
		return fmt.Errorf("id MUST NOT be present")
	}

	if vc.Issued == nil {
		return fmt.Errorf("issuance date MUST be present")
	}

	if vc.Expired == nil {
		return fmt.Errorf("expiration date MUST be present")
	}

	if vc.Subject == nil {
		return fmt.Errorf("subject MUST be present")
	}

	return validateSubject(vc.Subject, did, origin)
}

func validateJWT(vc *verifiable.Credential, did, origin string) error {
	jsonWebToken, _, err := jwt.Parse(vc.JWT, jwt.WithSignatureVerifier(&noVerifier{}))
	if err != nil {
		return fmt.Errorf("parse JWT: %w", err)
	}

	if err := validateJWTHeader(jsonWebToken.Headers); err != nil {
		return err
	}

	if err := validateJWTPayload(vc, jsonWebToken.Payload, did); err != nil {
		return err
	}

	if err := validateDomainLinkageCredential(vc, did, origin); err != nil {
		return err
	}

	// TODO: vc MUST be equal to the LD Proof Format without the proof property
	// Having issues with time format being lost when parsing VC from JWT
	return nil
}

func validateJWTHeader(headers jose.Headers) error {
	_, ok := headers.Algorithm()
	if !ok {
		return fmt.Errorf("alg MUST be present in the JWT Header")
	}

	_, ok = headers.KeyID()
	if !ok {
		return fmt.Errorf("kid MUST be present in the JWT Header")
	}

	// relaxing rule 'typ MUST NOT be present in the JWT Header' due to interop
	typ, ok := headers.Type()
	if ok && typ != jwt.TypeJWT {
		return fmt.Errorf("typ is not JWT")
	}

	allowed := []string{jose.HeaderAlgorithm, jose.HeaderKeyID, jose.HeaderType}

	err := verifyAllowedProperties(headers, allowed)
	if err != nil {
		return fmt.Errorf("JWT Header: %w", err)
	}

	return nil
}

func validateJWTPayload(vc *verifiable.Credential, payload map[string]interface{}, did string) error {
	// iat added for interop
	allowedProperties := []string{"exp", "iss", "nbf", "sub", "vc", "iat"}

	err := verifyAllowedProperties(payload, allowedProperties)
	if err != nil {
		return fmt.Errorf("JWT Payload: %w", err)
	}

	return validateJWTClaims(vc, did)
}

func validateJWTClaims(vc *verifiable.Credential, did string) error {
	jwtClaims, err := vc.JWTClaims(false)
	if err != nil {
		return err
	}

	if jwtClaims.Issuer != did {
		return fmt.Errorf("iss MUST be equal to credentialSubject.id")
	}

	if jwtClaims.Subject != did {
		return fmt.Errorf("sub MUST be equal to credentialSubject.id")
	}

	return nil
}

func contains(v string, values []string) bool {
	for _, val := range values {
		if v == val {
			return true
		}
	}

	return false
}

func validateSubject(subject interface{}, did, origin string) error {
	switch s := subject.(type) {
	case []verifiable.Subject:
		if len(s) > 1 {
			// TODO: Can we have more than one subject in this case
			return fmt.Errorf("encountered multiple subjects")
		}

		subject := s[0]

		if subject.ID == "" {
			return fmt.Errorf("credentialSubject.id MUST be present")
		}

		_, err := diddoc.Parse(subject.ID)
		if err != nil {
			return fmt.Errorf("credentialSubject.id MUST be a DID: %w", err)
		}

		objOrigin, ok := subject.CustomFields["origin"]
		if !ok {
			return fmt.Errorf("credentialSubject.origin MUST be present")
		}

		sOrigin, ok := objOrigin.(string)
		if !ok {
			return fmt.Errorf("credentialSubject.origin MUST be string")
		}

		// domain linkage credential format is valid - now check did configuration resource verification rules
		// https://identity.foundation/.well-known/resources/did-configuration/#did-configuration-resource-verification

		// subject ID must equal requested DID
		if subject.ID != did {
			return fmt.Errorf("credential subject ID[%s] is different from requested DID[%s]", subject.ID, did)
		}

		// subject origin must match the origin the resource was requested from
		err = validateOrigin(sOrigin, origin)
		if err != nil {
			return err
		}

	default:
		return fmt.Errorf("unexpected interface[%T] for subject", subject)
	}

	return nil
}

func validateOrigin(origin1, origin2 string) error {
	url1, err := url.Parse(origin1)
	if err != nil {
		return err
	}

	url2, err := url.Parse(origin2)
	if err != nil {
		return err
	}

	// Browsers define same origin based on the following pieces of data:
	// The protocol (e.g., HTTP or HTTPS)
	// The port, if available
	// The host
	if url1.Host != url2.Host || url1.Scheme != url2.Scheme || url1.Port() != url2.Port() {
		return fmt.Errorf("origin[%s] and domain origin[%s] are different", origin1, origin2)
	}

	return nil
}

func getCredentials(linkedDIDs []interface{}, did, domain string, opts ...verifiable.CredentialOpt) ([][]byte, error) {
	var credentialsForDIDAndDomain [][]byte

	for _, linkedDID := range linkedDIDs {
		var rawBytes []byte

		var err error

		switch linkedDID := linkedDID.(type) {
		case string: // JWT
			rawBytes = []byte(linkedDID)
		case map[string]interface{}: // Linked Data
			rawBytes, err = json.Marshal(linkedDID)
			if err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("unexpected interface[%T] for linked DID", linkedDID)
		}

		vc, err := verifiable.ParseCredential(rawBytes, opts...)
		if err != nil {
			// failed to parse credential - continue to next one
			logger.Infof("skipping credential due to error: %s", string(rawBytes), err.Error())

			continue
		}

		if vc.Issuer.ID != did {
			logger.Infof("skipping credential since issuer[%s] is different from DID[%s]", vc.Issuer.ID, did)

			continue
		}

		err = isValidDomainLinkageCredential(vc, did, domain)
		if err != nil {
			logger.Warnf("credential is not a valid domain linkage credential for DID[%s] and domain[%s]: %s",
				did, domain, err.Error())

			continue
		}

		credentialsForDIDAndDomain = append(credentialsForDIDAndDomain, rawBytes)
	}

	if len(credentialsForDIDAndDomain) == 0 {
		return nil, fmt.Errorf("domain linkage credential(s) not found")
	}

	return credentialsForDIDAndDomain, nil
}

// noVerifier is used when no JWT signature verification is needed.
// To be used with precaution.
type noVerifier struct{}

func (v noVerifier) Verify(_ jose.Headers, _, _, _ []byte) error {
	return nil
}

func getParseCredentialOptions(disableProofCheck bool, opts *didConfigOpts) []verifiable.CredentialOpt {
	var credOpts []verifiable.CredentialOpt

	credOpts = append(credOpts,
		verifiable.WithNoCustomSchemaCheck(),
		verifiable.WithJSONLDDocumentLoader(opts.jsonldDocumentLoader),
		verifiable.WithStrictValidation())

	if disableProofCheck {
		credOpts = append(credOpts, verifiable.WithDisabledProofCheck())
	} else {
		credOpts = append(credOpts,
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(opts.didResolver).PublicKeyFetcher()))
	}

	return credOpts
}
