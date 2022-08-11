/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"errors"
	"time"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

func (s *SDKSteps) issueCredential(issuer, issuedAt, subject, holder string) error {
	err := s.createDID(issuer, holder)
	if err != nil {
		return err
	}

	vcToIssue, err := s.createVC(issuedAt, subject, issuer)
	if err != nil {
		return err
	}

	vcBytes, err := s.addVCProof(vcToIssue, issuer)
	if err != nil {
		return err
	}

	s.issuedVCBytes = vcBytes

	return nil
}

func (s *SDKSteps) verifyCredential(holder string) error {
	vdr := s.bddContext.AgentCtx[holder].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()

	loader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	s.issuedVC, err = verifiable.ParseCredential(s.issuedVCBytes,
		verifiable.WithPublicKeyFetcher(pKeyFetcher),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	if s.issuedVC == nil {
		return errors.New("received nil credential")
	}

	return nil
}

func (s *SDKSteps) createVC(issuedAt, subject, issuer string) (*verifiable.Credential, error) {
	const dateLayout = "2006-01-02"

	issued, err := time.Parse(dateLayout, issuedAt)
	if err != nil {
		return nil, err
	}

	vcToIssue := &verifiable.Credential{
		Context: []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://www.w3.org/2018/credentials/examples/v1",
		},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential",
		},
		Subject: subject,
		Issuer: verifiable.Issuer{
			ID:           s.getPublicDID(issuer).ID,
			CustomFields: verifiable.CustomFields{"name": issuer},
		},
		Issued: util.NewTime(issued),
	}

	return vcToIssue, nil
}

func (s *SDKSteps) addVCProof(vc *verifiable.Credential, issuer string) ([]byte, error) {
	doc := s.getPublicDID(issuer)
	pubKeyID := doc.VerificationMethod[0].ID

	jwtClaims, err := vc.JWTClaims(false)
	if err != nil {
		return nil, err
	}

	publicKeyJWK := s.bddContext.PublicKeys[issuer]

	keyType, err := publicKeyJWK.KeyType()
	if err != nil {
		return nil, err
	}

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(keyType)
	if err != nil {
		return nil, err
	}

	signer := s.getSigner(issuer)

	jws, err := jwtClaims.MarshalJWS(jwsAlgo, signer, pubKeyID)
	if err != nil {
		return nil, err
	}

	return []byte(jws), nil
}
