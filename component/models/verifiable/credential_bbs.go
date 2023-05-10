/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/component/models/signature/suite/bbsblssignatureproof2020"
	jsonutil "github.com/hyperledger/aries-framework-go/component/models/util/json"
)

// GenerateBBSSelectiveDisclosure generate BBS+ selective disclosure from one BBS+ signature.
func (vc *Credential) GenerateBBSSelectiveDisclosure(revealDoc map[string]interface{},
	nonce []byte, opts ...CredentialOpt) (*Credential, error) {
	if len(vc.Proofs) == 0 {
		return nil, errors.New("expected at least one proof present")
	}

	vcOpts := getCredentialOpts(opts)
	jsonldProcessorOpts := mapJSONLDProcessorOpts(&vcOpts.jsonldCredentialOpts)

	if vcOpts.publicKeyFetcher == nil {
		return nil, errors.New("public key fetcher is not defined")
	}

	suite := bbsblssignatureproof2020.New()

	vcDoc, err := jsonutil.ToMap(vc)
	if err != nil {
		return nil, err
	}

	keyResolver := &keyResolverAdapter{vcOpts.publicKeyFetcher}

	vcWithSelectiveDisclosureDoc, err := suite.SelectiveDisclosure(vcDoc, revealDoc, nonce,
		keyResolver, jsonldProcessorOpts...)
	if err != nil {
		return nil, fmt.Errorf("create VC selective disclosure: %w", err)
	}

	vcWithSelectiveDisclosureBytes, err := json.Marshal(vcWithSelectiveDisclosureDoc)
	if err != nil {
		return nil, err
	}

	opts = append(opts, WithDisabledProofCheck())

	return ParseCredential(vcWithSelectiveDisclosureBytes, opts...)
}
