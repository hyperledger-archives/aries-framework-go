/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"time"

	"github.com/btcsuite/btcutil/base58"
	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
)

// SDKSteps is steps for verifiable credentials using client SDK
type SDKSteps struct {
	bddContext    *context.BDDContext
	issuedVCBytes []byte
}

// NewVerifiableCredentialSDKSteps creates steps for verifiable credential with SDK
func NewVerifiableCredentialSDKSteps() *SDKSteps {
	return &SDKSteps{}
}

const (
	// TODO support JsonWebSignature2020 and EcdsaSecp256k1Signature2019 signature suites
	//  (https://github.com/hyperledger/aries-framework-go/issues/1596)
	jwsLinkedDataProofEd25519Signature2018 = "JWS Ed25519Signature2018 Linked data"

	jwsProof = "JWS"
)

// SetContext is called before every scenario is run with a fresh new context
func (s *SDKSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers Verifiable Credential steps.
func (s *SDKSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" issues credential at "([^"]*)" regarding "([^"]*)" to "([^"]*)" with "([^"]*)" proof$`, s.issueCredential) //nolint:lll
	gs.Step(`^"([^"]*)" receives the credential and verifies it$`, s.verifyCredential)
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
			ID:           s.getPublicDID(issuer).ID,
			CustomFields: verifiable.CustomFields{"name": issuer},
		},
		Issued: util.NewTime(issued),
	}

	return vcToIssue, nil
}

func (s *SDKSteps) addVCProof(vc *verifiable.Credential, issuer, proofType string) ([]byte, error) {
	doc := s.getPublicDID(issuer)
	pubKey := doc.PublicKey[0]

	kms := s.bddContext.AgentCtx[issuer].Signer()
	signer := newSigner(kms, base58.Encode(pubKey.Value))

	switch proofType {
	case jwsLinkedDataProofEd25519Signature2018:
		err := vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
			SignatureType:           "Ed25519Signature2018",
			Suite:                   ed25519signature2018.New(suite.WithSigner(signer)),
			SignatureRepresentation: verifiable.SignatureJWS,
			Created:                 &vc.Issued.Time,
			VerificationMethod:      pubKey.ID,
		})
		if err != nil {
			return nil, err
		}

		return vc.MarshalJSON()

	case jwsProof:
		jwtClaims, err := vc.JWTClaims(false)
		if err != nil {
			return nil, err
		}

		jws, err := jwtClaims.MarshalJWS(verifiable.EdDSA, signer, pubKey.ID)
		if err != nil {
			return nil, err
		}

		return []byte(jws), nil

	default:
		return nil, errors.New("unsupported proof type: " + proofType)
	}
}

func (s *SDKSteps) verifyCredential(holder string) error {
	vdriRegistry := s.bddContext.AgentCtx[holder].VDRIRegistry()
	pKeyFetcher := verifiable.NewDIDKeyResolver(vdriRegistry).PublicKeyFetcher()

	sigSuite := ed25519signature2018.New(suite.WithVerifier(ed25519signature2018.NewPublicKeyVerifier()))

	parsedVC, err := verifiable.ParseCredential(s.issuedVCBytes,
		verifiable.WithPublicKeyFetcher(pKeyFetcher),
		verifiable.WithEmbeddedSignatureSuites(sigSuite))
	if err != nil {
		return err
	}

	if parsedVC == nil {
		return errors.New("received nil credential")
	}

	return nil
}

func (s *SDKSteps) getPublicDID(agentName string) *did.Doc {
	return s.bddContext.PublicDIDDocs[agentName]
}

func (s *SDKSteps) createDID(issuer, holder string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := issuer + "," + holder
	agentSDK := agent.NewSDKSteps()
	agentSDK.SetContext(s.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	if err := didresolver.CreateDIDDocument(s.bddContext, participants, acceptDidMethod); err != nil {
		return err
	}

	didExchangeSDK := bddDIDExchange.NewDIDExchangeSDKSteps()
	didExchangeSDK.SetContext(s.bddContext)

	return didExchangeSDK.WaitForPublicDID(participants, 10)
}
