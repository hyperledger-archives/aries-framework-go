/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletjsonld

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

func (s *SDKSteps) queryPresentations(verifier, issuer, rawQueryType string) error {
	queryType, err := wallet.GetQueryType(rawQueryType)
	if err != nil {
		return err
	}

	query, err := s.getQuery(queryType, s.getPublicDID(issuer).ID)
	if err != nil {
		return err
	}

	s.query = credentialsQuery{
		queryType: queryType,
		raw:       query,
	}

	return nil
}

func (s *SDKSteps) addResolvedPresentationProof(holder string) error {
	err := s.createKeyPairWallet(holder, s.crypto)
	if err != nil {
		return err
	}

	err = s.createDid(holder)
	if err != nil {
		return err
	}

	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	err = s.signPresentations(holder, walletInstance)

	return err
}

func (s *SDKSteps) signPresentations(
	agent string,
	walletInstance *wallet.Wallet) error {
	presentations := make([]*verifiable.Presentation, 0, len(s.query.resolved))

	for _, vp := range s.query.resolved {
		vp.Context = append(vp.Context, "https://w3id.org/security/suites/jws-2020/v1")

		vpSigned, err := walletInstance.Prove(s.token,
			&wallet.ProofOptions{
				Controller: s.getPublicDID(agent).ID,
				ProofType:  wallet.JSONWebSignature2020,
				ProofRepresentation: func() *verifiable.SignatureRepresentation {
					r := verifiable.SignatureJWS
					return &r
				}(),
			},
			wallet.WithPresentationToProve(vp),
		)
		if err != nil {
			return err
		}

		presentations = append(presentations, vpSigned)
	}

	s.query.resolved = presentations

	return nil
}

func (s *SDKSteps) receivePresentationsAndVerify(verifier, issuer string) error {
	for _, vp := range s.query.resolved {
		b, err := vp.MarshalJSON()
		if err != nil {
			return err
		}

		_, err = s.verifyPresentation(issuer, b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SDKSteps) verifyPresentation(agent string, vp []byte) (*verifiable.Presentation, error) {
	vdr := s.bddContext.AgentCtx[agent].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()
	loader := s.bddContext.AgentCtx[agent].JSONLDDocumentLoader()

	presentation, err := verifiable.ParsePresentation(vp,
		verifiable.WithPresPublicKeyFetcher(pKeyFetcher),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	if presentation == nil {
		return nil, errors.New("received nil presentation")
	}

	return presentation, nil
}
