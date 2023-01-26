/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/holder"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
)

type marshalDisclosureOpts struct {
	includeAllDisclosures bool
	discloseIfAvailable   []string
	discloseRequired      []string
	holderBinding         *holder.BindingInfo
	signer                jose.Signer
	signingKeyID          string
}

// MarshalDisclosureOption provides an option for Credential.MarshalWithDisclosure.
type MarshalDisclosureOption func(opts *marshalDisclosureOpts)

// TODO: should DiscloseGiven(IfAvailable|Required) have path semantics for disclosure?

// DiscloseGivenIfAvailable sets that the disclosures with the given claim names will be disclosed by
// Credential.MarshalWithDisclosure.
//
// If any name provided does not have a matching disclosure, Credential.MarshalWithDisclosure will skip the name.
//
// Will result in an error if this option is provided alongside DiscloseAll.
func DiscloseGivenIfAvailable(disclosureNames []string) MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.discloseIfAvailable = disclosureNames
	}
}

// DiscloseGivenRequired sets that the disclosures with the given claim names will be disclosed by
// Credential.MarshalWithDisclosure.
//
// If any name provided does not have a matching disclosure, Credential.MarshalWithDisclosure will return an error.
//
// Will result in an error if this option is provided alongside DiscloseAll.
func DiscloseGivenRequired(disclosureNames []string) MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.discloseRequired = disclosureNames
	}
}

// DiscloseAll sets that all disclosures in the given Credential will be disclosed by Credential.MarshalWithDisclosure.
//
// Will result in an error if this option is provided alongside DiscloseGivenIfAvailable or DiscloseGivenRequired.
func DiscloseAll() MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.includeAllDisclosures = true
	}
}

// DisclosureHolderBinding option configures Credential.MarshalWithDisclosure to include a holder binding.
func DisclosureHolderBinding(binding *holder.BindingInfo) MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.holderBinding = binding
	}
}

// DisclosureSigner option provides Credential.MarshalWithDisclosure with a signer that will be used to create an SD-JWT
// if the given Credential wasn't already parsed from SD-JWT.
func DisclosureSigner(signer jose.Signer, signingKeyID string) MarshalDisclosureOption {
	return func(opts *marshalDisclosureOpts) {
		opts.signer = signer
		opts.signingKeyID = signingKeyID
	}
}

// MarshalWithDisclosure marshals a SD-JWT credential in combined format for presentation, including precisely
// the disclosures indicated by provided options, and optionally a holder binding if given the requisite option.
func (vc *Credential) MarshalWithDisclosure(opts ...MarshalDisclosureOption) (string, error) {
	options := &marshalDisclosureOpts{}

	for _, opt := range opts {
		opt(options)
	}

	if options.includeAllDisclosures && (len(options.discloseIfAvailable) > 0 || len(options.discloseRequired) > 0) {
		return "", fmt.Errorf("incompatible options provided")
	}

	if vc.JWT != "" && vc.SDJWTHashAlg != "" {
		return filterSDJWTVC(vc, options)
	}

	if options.signer == nil {
		return "", fmt.Errorf("credential needs signer to create SD-JWT")
	}

	return createSDJWTPresentation(vc, options)
}

func filterSDJWTVC(vc *Credential, options *marshalDisclosureOpts) (string, error) {
	disclosureCodes, err := filteredDisclosureCodes(vc.SDJWTDisclosures, options)
	if err != nil {
		return "", err
	}

	cf := common.CombinedFormatForPresentation{
		SDJWT:       vc.JWT,
		Disclosures: disclosureCodes,
	}

	if options.holderBinding != nil {
		cf.HolderBinding, err = holder.CreateHolderBinding(options.holderBinding)
		if err != nil {
			return "", fmt.Errorf("failed to create holder binding: %w", err)
		}
	}

	return cf.Serialize(), nil
}

func createSDJWTPresentation(vc *Credential, options *marshalDisclosureOpts) (string, error) {
	issued, err := makeSDJWT(vc, options.signer, options.signingKeyID)
	if err != nil {
		return "", fmt.Errorf("creating SD-JWT from Credential: %w", err)
	}

	disclosureClaims, err := common.GetDisclosureClaims(issued.Disclosures)
	if err != nil {
		return "", fmt.Errorf("parsing disclosure claims from vc sdjwt: %w", err)
	}

	disclosureCodes, err := filteredDisclosureCodes(disclosureClaims, options)
	if err != nil {
		return "", err
	}

	var presOpts []holder.Option

	if options.holderBinding != nil {
		presOpts = append(presOpts, holder.WithHolderBinding(options.holderBinding))
	}

	issuedSerialized, err := issued.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serializing SD-JWT for presentation: %w", err)
	}

	combinedSDJWT, err := holder.CreatePresentation(issuedSerialized, disclosureCodes, presOpts...)
	if err != nil {
		return "", fmt.Errorf("create SD-JWT presentation: %w", err)
	}

	return combinedSDJWT, nil
}

func filteredDisclosureCodes(
	availableDisclosures []*common.DisclosureClaim,
	options *marshalDisclosureOpts,
) ([]string, error) {
	var (
		useDisclosures  []*common.DisclosureClaim
		err             error
		disclosureCodes []string
	)

	if options.includeAllDisclosures {
		useDisclosures = availableDisclosures
	} else {
		useDisclosures, err = filterDisclosures(availableDisclosures,
			options.discloseIfAvailable, options.discloseRequired)
		if err != nil {
			return nil, err
		}
	}

	for _, disclosure := range useDisclosures {
		disclosureCodes = append(disclosureCodes, disclosure.Disclosure)
	}

	return disclosureCodes, nil
}

func filterDisclosures(
	disclosures []*common.DisclosureClaim,
	ifAvailable, required []string,
) ([]*common.DisclosureClaim, error) {
	ifAvailMap := map[string]*common.DisclosureClaim{}
	reqMap := map[string]*common.DisclosureClaim{}

	for _, name := range ifAvailable {
		ifAvailMap[name] = nil
	}

	for _, name := range required {
		reqMap[name] = nil

		delete(ifAvailMap, name) // avoid listing a disclosure twice, if it's in both lists
	}

	for _, disclosure := range disclosures {
		if _, ok := ifAvailMap[disclosure.Name]; ok {
			ifAvailMap[disclosure.Name] = disclosure
		}

		if _, ok := reqMap[disclosure.Name]; ok {
			reqMap[disclosure.Name] = disclosure
		}
	}

	var out []*common.DisclosureClaim

	for _, claim := range ifAvailMap {
		if claim != nil {
			out = append(out, claim)
		}
	}

	for _, claim := range reqMap {
		if claim == nil {
			return nil, fmt.Errorf("disclosure list missing required claim")
		}

		out = append(out, claim)
	}

	return out, nil
}

// MakeSDJWT creates an SD-JWT in combined format for issuance, with all fields in credentialSubject converted
// recursively into selectively-disclosable SD-JWT claims.
func (vc *Credential) MakeSDJWT(signer jose.Signer, signingKeyID string) (string, error) {
	sdjwt, err := makeSDJWT(vc, signer, signingKeyID)
	if err != nil {
		return "", err
	}

	sdjwtSerialized, err := sdjwt.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serializing SD-JWT: %w", err)
	}

	return sdjwtSerialized, nil
}

func makeSDJWT(vc *Credential, signer jose.Signer, signingKeyID string) (*issuer.SelectiveDisclosureJWT, error) {
	claims, err := vc.JWTClaims(false)
	if err != nil {
		return nil, fmt.Errorf("constructing VC JWT claims: %w", err)
	}

	claimBytes, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}

	claimMap := map[string]interface{}{}

	err = json.Unmarshal(claimBytes, &claimMap)
	if err != nil {
		return nil, err
	}

	headers := map[string]interface{}{
		jose.HeaderKeyID: signingKeyID,
	}

	sdjwt, err := issuer.NewFromVC(claimMap, headers, signer, issuer.WithStructuredClaims(true))
	if err != nil {
		return nil, fmt.Errorf("creating SD-JWT from VC: %w", err)
	}

	return sdjwt, nil
}