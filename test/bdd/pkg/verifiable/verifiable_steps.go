/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
)

// SDKSteps is steps for verifiable credentials using client SDK
type SDKSteps struct {
	bddContext    *context.BDDContext
	issuedVCBytes []byte
	proofType     string
	pubKey        ed25519.PublicKey
}

// NewVerifiableCredentialSDKSteps creates steps for verifiable credential with SDK
func NewVerifiableCredentialSDKSteps(ctx *context.BDDContext) *SDKSteps {
	return &SDKSteps{
		bddContext: ctx,
	}
}

const (
	jwsLinkedDataProof = "JWS Linked data"

	jwsProof = "JWS"
)

// RegisterSteps registers Verifiable Credential steps.
func (s *SDKSteps) RegisterSteps(suite *godog.Suite) {
	suite.Step(`^"([^"]*)" issues credential at "([^"]*)" regarding "([^"]*)" to "([^"]*)" with "([^"]*)" proof$`, s.issueCredential) //nolint:lll
	suite.Step(`^"([^"]*)" receives the credential and verifies it$`, s.verifyCredential)
}

func (s *SDKSteps) issueCredential(issuer, issuedAt, subject, holder, proofType string) error {
	err := s.createDID(issuer, holder)
	if err != nil {
		return err
	}

	vcToIssue, err := s.createVC(issuedAt, subject, issuer)
	if err != nil {
		return err
	}

	vcBytes, err := s.addVCProof(vcToIssue, issuer, proofType)
	if err != nil {
		return err
	}

	s.issuedVCBytes = vcBytes

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
			"https://www.w3.org/2018/credentials/examples/v1"},
		ID: "http://example.edu/credentials/1872",
		Types: []string{
			"VerifiableCredential",
			"UniversityDegreeCredential"},
		Subject: subject,
		Issuer: verifiable.Issuer{
			ID:   s.getPublicDID(issuer).ID,
			Name: issuer,
		},
		Issued: &issued,
	}

	return vcToIssue, nil
}

func (s *SDKSteps) addVCProof(vc *verifiable.Credential, issuer, proofType string) ([]byte, error) {
	doc := s.getPublicDID(issuer)
	pubKey := doc.PublicKey[0]

	kms := s.bddContext.AgentCtx[issuer].Signer()

	s.proofType = proofType

	switch proofType {
	case jwsLinkedDataProof:
		verificationMethod := doc.ID + pubKey.ID

		err := addJWSLinkedDataProof(vc, newSigner(kms, base58.Encode(pubKey.Value)), verificationMethod)
		if err != nil {
			return nil, err
		}

		return vc.MarshalJSON()

	case jwsProof:
		// TODO to be improved at https://github.com/hyperledger/aries-framework-go/issues/339:
		//  1) use KMS for signing
		//  2) do not keep public key, should be resolved by sidetree
		jwtClaims, err := vc.JWTClaims(false)
		if err != nil {
			return nil, err
		}

		pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}

		// keep pubKey to be used later for verification by a Holder
		s.pubKey = pubKey

		jws, err := jwtClaims.MarshalJWS(verifiable.EdDSA, privKey, "key-1")
		if err != nil {
			return nil, err
		}

		return []byte(jws), nil

	default:
		return nil, errors.New("unsupported proof type: " + proofType)
	}
}

func (s *SDKSteps) verifyCredential(holder string) error {
	switch s.proofType {
	case jwsLinkedDataProof:
		return s.verifyCredentialWithLinkedDataProof(holder)

	case jwsProof:
		return s.verifyCredentialWithJWSProof()

	default:
		return errors.New("unsupported proof type: " + s.proofType)
	}
}

func (s *SDKSteps) getPublicDID(agentName string) *did.Doc {
	return s.bddContext.PublicDIDs[agentName]
}

func (s *SDKSteps) createDID(issuer, holder string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := issuer + "," + holder
	agentSDK := agent.NewSDKSteps(s.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	return didresolver.CreateDIDDocument(s.bddContext, participants, acceptDidMethod)
}

func (s *SDKSteps) verifyCredentialWithLinkedDataProof(holder string) error {
	vdriRegistry := s.bddContext.AgentCtx[holder].VDRIRegistry()
	pKeyFetcher := verifiable.NewDIDKeyResolver(vdriRegistry).PublicKeyFetcher()

	parsedVC, _, err := verifiable.NewCredential(s.issuedVCBytes,
		verifiable.WithPublicKeyFetcher(pKeyFetcher),
		verifiable.WithEmbeddedSignatureSuites(ed25519signature2018.New()))
	if err != nil {
		return err
	}

	if parsedVC == nil {
		return errors.New("received nil credential")
	}

	return nil
}

func (s *SDKSteps) verifyCredentialWithJWSProof() error {
	parsedVC, _, err := verifiable.NewCredential(s.issuedVCBytes,
		verifiable.WithPublicKeyFetcher(verifiable.SingleKey(s.pubKey)))
	if err != nil {
		return err
	}

	if parsedVC == nil {
		return errors.New("received nil credential")
	}

	return nil
}

func addJWSLinkedDataProof(vc *verifiable.Credential, signer *signer, verificationMethod string) error {
	suite := ed25519signature2018.New(ed25519signature2018.WithSigner(signer))

	return vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   suite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 vc.Issued,
		VerificationMethod:      verificationMethod,
	})
}
