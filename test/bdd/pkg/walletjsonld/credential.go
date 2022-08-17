/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package walletjsonld

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"time"

	jsonldsig "github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
)

func (s *SDKSteps) issueCredential(issuer, issuedAt, subject, holder string) error {
	err := s.createKeyPairLocalKMS(issuer, s.crypto)
	if err != nil {
		return err
	}

	err = s.createDid(issuer)
	if err != nil {
		return err
	}

	vcToIssue, err := s.createRawCredential(issuedAt, subject, issuer)
	if err != nil {
		return err
	}

	vcBytes, err := s.addCredentialProof(vcToIssue, issuer)
	if err != nil {
		return err
	}

	s.vcBytes[issuer] = vcBytes

	return nil
}

func (s *SDKSteps) createUnsecuredCredential(holder, issuedAt, subject string) error {
	err := s.createKeyPairWallet(holder, s.crypto)
	if err != nil {
		return err
	}

	err = s.createDid(holder)
	if err != nil {
		return err
	}

	vc, err := s.createRawCredential(issuedAt, subject, holder)
	if err != nil {
		return err
	}

	vcBytes, err := vc.MarshalJSON()
	if err != nil {
		return err
	}

	s.vcBytes[holder] = vcBytes

	return nil
}

func (s *SDKSteps) resolveCredentialsQuery(holder string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	vpUnsigned, err := walletInstance.Query(s.token,
		&wallet.QueryParams{Type: s.query.queryType.Name(), Query: []json.RawMessage{s.query.raw}})
	if err != nil {
		return err
	}

	if vpUnsigned == nil {
		return fmt.Errorf("empty presentation list")
	}

	s.query.resolved = vpUnsigned

	return nil
}

func (s *SDKSteps) issueCredentialsUsingWallet(holder string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	vcBytes, err := s.issueCredentialsWallet(holder, s.vcBytes[holder], walletInstance)
	if err != nil {
		return err
	}

	s.vcBytes[holder] = vcBytes

	return nil
}

func (s *SDKSteps) issueCredentialsWallet(agent string, vcUnsecured []byte, walletInstance *wallet.Wallet) ([]byte, error) { //nolint:lll
	vc, err := walletInstance.Issue(s.token, vcUnsecured, &wallet.ProofOptions{
		Controller: s.getPublicDID(agent).ID,
		ProofType:  wallet.JSONWebSignature2020,
		ProofRepresentation: func() *verifiable.SignatureRepresentation {
			r := verifiable.SignatureJWS
			return &r
		}(),
	})
	if err != nil {
		return nil, err
	}

	return vc.MarshalJSON()
}

func (s *SDKSteps) receiveCredentialsAndVerify(verifier, issuer string) error {
	for _, vp := range s.query.resolved {
		for _, rawVc := range vp.Credentials() {
			vc, ok := rawVc.(*verifiable.Credential)
			if !ok {
				return fmt.Errorf("invalid resolved credentials type %s", reflect.TypeOf(vc).String())
			}

			b, err := vc.MarshalJSON()
			if err != nil {
				return err
			}

			err = s.verifyCredential(issuer, b)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *SDKSteps) verifyCredential(issuer string, vcBytes []byte) error {
	vdr := s.bddContext.AgentCtx[issuer].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()
	loader := s.bddContext.AgentCtx[issuer].JSONLDDocumentLoader()

	credentials, err := verifiable.ParseCredential(vcBytes,
		verifiable.WithPublicKeyFetcher(pKeyFetcher),
		verifiable.WithJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	if credentials == nil {
		return errors.New("received nil credential")
	}

	return nil
}

func (s *SDKSteps) verifyGetAllCredential(verifier, issuer string) error {
	vcBytes := s.getAllCredentialsResult[s.getCredentialID(issuer)]

	return s.verifyCredential(issuer, vcBytes)
}

func (s *SDKSteps) createRawCredential(issuedAt, subject, issuer string) (*verifiable.Credential, error) {
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
		ID: s.getCredentialID(issuer),
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

func (s *SDKSteps) getCredentialID(issuer string) string {
	return fmt.Sprintf("%s-%s", issuer, s.getPublicDID(issuer).ID)
}

func (s *SDKSteps) addCredentialProof(vc *verifiable.Credential, issuer string) ([]byte, error) {
	doc := s.getPublicDID(issuer)
	cr := s.bddContext.AgentCtx[issuer].Crypto()
	kh := s.bddContext.KeyHandles[issuer]
	signer := newCryptoSigner(cr, kh)
	loader := s.bddContext.AgentCtx[issuer].JSONLDDocumentLoader()

	err := vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		Suite:                   jsonwebsignature2020.New(suite.WithSigner(signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &vc.Issued.Time,
		VerificationMethod:      doc.ID + doc.VerificationMethod[0].ID,
	}, jsonldsig.WithDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	return vc.MarshalJSON()
}

func (s *SDKSteps) addCredentialsToWallet(holder, issuer string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	return walletInstance.Add(s.token, wallet.Credential, s.vcBytes[issuer])
}

func (s *SDKSteps) queryAllCredentials(verifier, holder string) error {
	walletInstance := s.wallet
	if walletInstance == nil {
		return fmt.Errorf("empty wallet")
	}

	queryResult, err := walletInstance.GetAll(s.token, wallet.Credential)
	if err != nil {
		return err
	}

	s.getAllCredentialsResult = queryResult

	return nil
}

func (s *SDKSteps) checkGetAllAmount(verifier, amount string) error {
	receivedAmount := len(s.getAllCredentialsResult)
	if strconv.Itoa(receivedAmount) != amount {
		return fmt.Errorf("received invalid credentials amount, expected: %s, got: %d", amount, receivedAmount)
	}

	return nil
}
