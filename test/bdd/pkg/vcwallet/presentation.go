/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

func (s *SDKSteps) queryPresentations(_, issuer, rawQueryType string) error {
	return s.queryPresentationWithFormat("", "", issuer, rawQueryType)
}

func (s *SDKSteps) queryPresentationWithFormat(_, format, issuer, rawQueryType string) error {
	queryTypeString := strings.Split(rawQueryType, "-")[0]

	queryType, err := wallet.GetQueryType(queryTypeString)
	if err != nil {
		return err
	}

	query, err := s.getQuery(rawQueryType, s.getPublicDID(issuer).ID, format)
	if err != nil {
		return err
	}

	s.query = credentialsQuery{
		queryType: queryType,
		raw:       query,
	}

	return nil
}

func (s *SDKSteps) addResolvedPresentationProof(holder, proofFormat string) error {
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

	var format wallet.ProofFormat

	switch proofFormat {
	case jwtFormat:
		format = wallet.ExternalJWTProofFormat
	case jsonLDFormat:
		format = wallet.EmbeddedLDProofFormat
	}

	err = s.signPresentations(holder, walletInstance, format)

	return err
}

func (s *SDKSteps) signPresentations(
	agent string,
	walletInstance *wallet.Wallet,
	format wallet.ProofFormat) error {
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
				ProofFormat: format,
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

func (s *SDKSteps) receivePresentationsAndVerify(_, issuer string) error {
	for _, vp := range s.query.resolved {
		b, err := vp.MarshalJSON()
		if err != nil {
			return err
		}

		err = s.verifyPresentation(issuer, b)
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *SDKSteps) receivePresentationsAndVerifyWithIssuer(_, holder, issuer string) error {
	issuerDoc := s.bddContext.PublicDIDDocs[issuer]

	for _, vp := range s.query.resolved {
		b, err := vp.MarshalJSON()
		if err != nil {
			return err
		}

		err = s.verifyPresentation(holder, b)
		if err != nil {
			return fmt.Errorf(
				"verify presentation: %w, issuer DID = %s, holder DID = %s",
				err,
				issuerDoc.ID,
				s.bddContext.PublicDIDDocs[holder].ID,
			)
		}
	}

	return nil
}

func (s *SDKSteps) verifyPresentation(agent string, vp []byte) error {
	vdr := s.bddContext.AgentCtx[agent].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()
	loader := s.bddContext.AgentCtx[agent].JSONLDDocumentLoader()

	presentation, err := verifiable.ParsePresentation(vp,
		verifiable.WithPresPublicKeyFetcher(pKeyFetcher),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	if presentation == nil {
		return errors.New("received nil presentation")
	}

	return nil
}
