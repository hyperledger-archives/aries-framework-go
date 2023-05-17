/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package peer

import (
	"fmt"
	"strings"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/did/endpoint"
	vdrapi "github.com/hyperledger/aries-framework-go/component/vdr/api"
	vdrspi "github.com/hyperledger/aries-framework-go/spi/vdr"
)

const (
	schemaResV1                = "https://w3id.org/did-resolution/v1"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"
	jsonWebKey2020             = "JsonWebKey2020"
	x25519KeyAgreementKey2019  = "X25519KeyAgreementKey2019"
	didcommV2MediaType         = "didcomm/v2"
)

// Create create new DID Document.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2466
func (v *VDR) Create(didDoc *did.Doc, opts ...vdrspi.DIDMethodOption) (*did.DocResolution, error) {
	docOpts := &vdrspi.DIDMethodOpts{Values: make(map[string]interface{})}
	// Apply options
	for _, opt := range opts {
		opt(docOpts)
	}

	store := false

	storeOpt := docOpts.Values["store"]
	if storeOpt != nil {
		var ok bool

		store, ok = storeOpt.(bool)
		if !ok {
			return nil, fmt.Errorf("store opt not boolean")
		}
	}

	if !store {
		docResolution, err := build(didDoc, docOpts)
		if err != nil {
			return nil, fmt.Errorf("create peer DID : %w", err)
		}

		didDoc = docResolution.DIDDocument
	}

	if err := v.storeDID(didDoc, nil); err != nil {
		return nil, err
	}

	return &did.DocResolution{Context: []string{schemaResV1}, DIDDocument: didDoc}, nil
}

// nolint: funlen,gocyclo,gocognit
func build(didDoc *did.Doc, docOpts *vdrspi.DIDMethodOpts) (*did.DocResolution, error) {
	if len(didDoc.VerificationMethod) == 0 && len(didDoc.KeyAgreement) == 0 {
		return nil, fmt.Errorf("verification method and key agreement are empty, at least one should be set")
	}

	mainVM, keyAgreementVM, err := buildDIDVMs(didDoc)
	if err != nil {
		return nil, err
	}

	// Service model to be included only if service type is provided through opts
	var service []did.Service

	for i := range didDoc.Service {
		if didDoc.Service[i].ID == "" {
			didDoc.Service[i].ID = uuid.New().String()
		}

		if didDoc.Service[i].Type == "" && docOpts.Values[DefaultServiceType] != nil {
			v, ok := docOpts.Values[DefaultServiceType].(string)
			if !ok {
				return nil, fmt.Errorf("defaultServiceType not string")
			}

			didDoc.Service[i].Type = v
		}

		uri, _ := didDoc.Service[i].ServiceEndpoint.URI() // nolint:errcheck

		// nolint:nestif
		if uri == "" && docOpts.Values[DefaultServiceEndpoint] != nil {
			switch didDoc.Service[i].Type {
			case vdrapi.DIDCommServiceType, vdrapi.LegacyServiceType:
				v, ok := docOpts.Values[DefaultServiceEndpoint].(string)
				if !ok {
					return nil, fmt.Errorf("defaultServiceEndpoint not string")
				}

				didDoc.Service[i].ServiceEndpoint = endpoint.NewDIDCommV1Endpoint(v)
			case vdrapi.DIDCommV2ServiceType:
				epArrayEntry := stringArray(docOpts.Values[DefaultServiceEndpoint])

				sp := endpoint.Endpoint{}

				if len(epArrayEntry) == 0 {
					sp = endpoint.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{{}})
				} else {
					for _, ep := range epArrayEntry {
						err = sp.UnmarshalJSON([]byte(ep))
						if err != nil {
							if strings.EqualFold(err.Error(), "endpoint data is not supported") {
								// if unmarshall failed, then use as string.
								sp = endpoint.NewDIDCommV2Endpoint([]endpoint.DIDCommV2Endpoint{
									{URI: ep, Accept: []string{didcommV2MediaType}},
								})
							}

							continue
						}

						break
					}
				}

				didDoc.Service[i].ServiceEndpoint = sp
			}
		}

		applyDIDCommKeys(i, didDoc)
		applyDIDCommV2Keys(i, didDoc)

		service = append(service, didDoc.Service[i])
	}

	// Created/Updated time
	t := time.Now()

	assertion := []did.Verification{{
		VerificationMethod: mainVM[0],
		Relationship:       did.AssertionMethod,
	}}

	authentication := []did.Verification{{
		VerificationMethod: mainVM[0],
		Relationship:       did.Authentication,
	}}

	var keyAgreement []did.Verification

	verificationMethods := mainVM

	if keyAgreementVM != nil {
		verificationMethods = append(verificationMethods, keyAgreementVM...)

		for _, ka := range keyAgreementVM {
			keyAgreement = append(keyAgreement, did.Verification{
				VerificationMethod: ka,
				Relationship:       did.KeyAgreement,
			})
		}
	}

	didDoc, err = NewDoc(
		verificationMethods,
		did.WithService(service),
		did.WithCreatedTime(t),
		did.WithUpdatedTime(t),
		did.WithAuthentication(authentication),
		did.WithAssertion(assertion),
		did.WithKeyAgreement(keyAgreement),
	)
	if err != nil {
		return nil, err
	}

	return &did.DocResolution{DIDDocument: didDoc}, nil
}

// stringEntry.
func stringEntry(entry interface{}) string {
	if entry == nil {
		return ""
	}

	return entry.(string)
}

// stringArray.
func stringArray(entry interface{}) []string {
	if entry == nil {
		return nil
	}

	entries, ok := entry.([]interface{})
	if !ok {
		if entryStr, ok := entry.(string); ok {
			return []string{entryStr}
		}

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

func applyDIDCommKeys(i int, didDoc *did.Doc) {
	if didDoc.Service[i].Type == vdrapi.DIDCommServiceType {
		didKey, _ := fingerprint.CreateDIDKey(didDoc.VerificationMethod[0].Value)
		didDoc.Service[i].RecipientKeys = []string{didKey}
		didDoc.Service[i].Priority = 0
	}

	if didDoc.Service[i].Type == vdrapi.LegacyServiceType {
		didDoc.Service[i].RecipientKeys = []string{base58.Encode(didDoc.VerificationMethod[0].Value)}
		didDoc.Service[i].Priority = 0
	}
}

func applyDIDCommV2Keys(i int, didDoc *did.Doc) {
	if didDoc.Service[i].Type == vdrapi.DIDCommV2ServiceType {
		didDoc.Service[i].RecipientKeys = []string{}
		didDoc.Service[i].Priority = 0

		for _, ka := range didDoc.KeyAgreement {
			kaID := ka.VerificationMethod.ID

			didDoc.Service[i].RecipientKeys = append(didDoc.Service[i].RecipientKeys, kaID)
		}
	}
}

func buildDIDVMs(didDoc *did.Doc) ([]did.VerificationMethod, []did.VerificationMethod, error) {
	var mainVM, keyAgreementVM []did.VerificationMethod

	// add all VMs, not only the first one.
	for _, vm := range didDoc.VerificationMethod {
		switch vm.Type {
		case ed25519VerificationKey2018:
			mainVM = append(mainVM, *did.NewVerificationMethodFromBytes(vm.ID, ed25519VerificationKey2018,
				"#id", vm.Value))
		case jsonWebKey2020:
			publicKey1, err := did.NewVerificationMethodFromJWK(vm.ID, jsonWebKey2020, "#id",
				vm.JSONWebKey())
			if err != nil {
				return nil, nil, err
			}

			mainVM = append(mainVM, *publicKey1)
		default:
			return nil, nil, fmt.Errorf("not supported VerificationMethod public key type: %s",
				didDoc.VerificationMethod[0].Type)
		}
	}

	for _, ka := range didDoc.KeyAgreement {
		switch ka.VerificationMethod.Type {
		case x25519KeyAgreementKey2019:
			keyAgreementVM = append(keyAgreementVM, *did.NewVerificationMethodFromBytes(
				ka.VerificationMethod.ID, x25519KeyAgreementKey2019, "",
				ka.VerificationMethod.Value))

		case jsonWebKey2020:
			kaVM, err := did.NewVerificationMethodFromJWK(ka.VerificationMethod.ID, jsonWebKey2020, "",
				ka.VerificationMethod.JSONWebKey())
			if err != nil {
				return nil, nil, err
			}

			keyAgreementVM = append(keyAgreementVM, *kaVM)
		default:
			return nil, nil, fmt.Errorf("not supported KeyAgreement public key type: %s", didDoc.VerificationMethod[0].Type)
		}
	}

	return mainVM, keyAgreementVM, nil
}
