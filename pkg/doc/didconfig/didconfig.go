/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package didconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	jsonld "github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/key"
)

var logger = log.New("aries-framework/doc/verifiable")

const (
	// ContextV1 of the DID document is the current V1 context name.
	ContextV1 = "https://identity.foundation/.well-known/did-configuration/v1"

	domainLinkageCredentialType = "DomainLinkageCredential"

	contextProperty    = "@context"
	linkedDIDsProperty = "linked_dids"
)

// didConfigOpts holds options for the DID Configuration decoding.
type didConfigOpts struct {
	jsonldDocumentLoader jsonld.DocumentLoader
	vdrRegistry          vdrapi.Registry
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
func WithVDRegistry(vdrRegistry vdrapi.Registry) DIDConfigurationOpt {
	return func(opts *didConfigOpts) {
		opts.vdrRegistry = vdrRegistry
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

	credentials, err := getCredentials(raw.LinkedDIDs, did, domain, didCfgOpts)
	if err != nil {
		return err
	}

	logger.Debugf("found %d domain linkage credential(s) for DID[%s] and domain[%s]", len(credentials), did, domain)

	for _, credBytes := range credentials {
		var credOpts []verifiable.CredentialOpt

		credOpts = append(credOpts,
			verifiable.WithPublicKeyFetcher(verifiable.NewVDRKeyResolver(didCfgOpts.vdrRegistry).PublicKeyFetcher()),
			verifiable.WithNoCustomSchemaCheck(),
			verifiable.WithJSONLDDocumentLoader(didCfgOpts.jsonldDocumentLoader),
			verifiable.WithStrictValidation())

		// this time we are parsing credential with proof check so DID will be resolved
		// and public key from did will be used to verify proof
		_, err := verifiable.ParseCredential(credBytes, credOpts...)
		if err == nil {
			// we found domain linkage credential with valid proof so all good
			return nil
		}

		// failed to verify credential proof - log info and continue to next one
		logger.Debugf("skipping domain linkage credential for DID[%s] and domain[%s] due to error: %s",
			did, domain, err.Error())
	}

	return fmt.Errorf("domain linkage credential(s) with valid proof not found")
}

func getDIDConfigurationOpts(opts []DIDConfigurationOpt) *didConfigOpts {
	didCfgOpts := &didConfigOpts{
		jsonldDocumentLoader: jsonld.NewDefaultDocumentLoader(http.DefaultClient),
		vdrRegistry:          vdr.New(vdr.WithVDR(key.New())),
	}

	for _, opt := range opts {
		opt(didCfgOpts)
	}

	return didCfgOpts
}

func verifyDidConfigurationProperties(data []byte) error {
	requiredKeys := []string{contextProperty, linkedDIDsProperty}
	allowedKeys := []string{contextProperty, linkedDIDsProperty}

	var didCfgMap map[string]interface{}

	err := json.Unmarshal(data, &didCfgMap)
	if err != nil {
		return fmt.Errorf("JSON unmarshalling of DID configuration bytes failed: %w", err)
	} else if didCfgMap == nil {
		return errors.New("DID configuration payload is not provided")
	}

	for _, required := range requiredKeys {
		if _, ok := didCfgMap[required]; !ok {
			return fmt.Errorf("key '%s' is required", required)
		}
	}

	for key := range didCfgMap {
		if !contains(key, allowedKeys) {
			return fmt.Errorf("key '%s' is not allowed", key)
		}
	}

	return nil
}

func isValidDomainLinkageCredential(vc *verifiable.Credential, did, origin string) error {
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

		if subject.ID != did {
			return fmt.Errorf("credential subject ID[%s] is different from requested did[%s]", subject.ID, did)
		}

		objOrigin, ok := subject.CustomFields["origin"]
		if !ok {
			return fmt.Errorf("credentialSubject.origin MUST be present")
		}

		sOrigin, ok := objOrigin.(string)
		if !ok {
			return fmt.Errorf("credentialSubject.origin MUST be string")
		}

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

func getCredentials(linkedDIDs []interface{}, did, domain string, opts *didConfigOpts) ([][]byte, error) {
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

		var credOpts []verifiable.CredentialOpt

		credOpts = append(credOpts,
			verifiable.WithDisabledProofCheck(),
			verifiable.WithNoCustomSchemaCheck(),
			verifiable.WithJSONLDDocumentLoader(opts.jsonldDocumentLoader),
			verifiable.WithStrictValidation())

		vc, err := verifiable.ParseCredential(rawBytes, credOpts...)
		if err != nil {
			// failed to parse credential - continue to next one
			logger.Debugf("skipping credential due to error: %s", string(rawBytes), err.Error())

			continue
		}

		if vc.Issuer.ID != did {
			logger.Debugf("skipping credential since issuer[%s] is different from DID[%s]", vc.Issuer.ID, did)

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
