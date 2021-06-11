/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/cucumber/godog"
	"github.com/piprate/json-gold/ld"

	"github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	jld "github.com/hyperledger/aries-framework-go/pkg/doc/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/jsonld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/signer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ecdsasecp256k1signature2019"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/ed25519signature2018"
	"github.com/hyperledger/aries-framework-go/pkg/doc/signature/suite/jsonwebsignature2020"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	bddagent "github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	bddDIDExchange "github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
	bddjsonld "github.com/hyperledger/aries-framework-go/test/bdd/pkg/jsonld"
)

// SDKSteps is steps for verifiable credentials using client SDK.
type SDKSteps struct {
	bddContext       *context.BDDContext
	issuedVCBytes    []byte
	secp256k1PrivKey *ecdsa.PrivateKey
}

// NewVerifiableCredentialSDKSteps creates steps for verifiable credential with SDK.
func NewVerifiableCredentialSDKSteps() *SDKSteps {
	return &SDKSteps{}
}

const (
	ldpEd25519Signature2018        = "Ed25519Signature2018 Linked Data"
	ldpJSONWebSignatureECP256      = "JsonWebSignature2020 (EC P256) Linked Data"
	ldpJSONWebSignatureEd25519     = "JsonWebSignature2020 (Ed25519) Linked Data"
	ldpJSONWebSignatureSecp256k1   = "JsonWebSignature2020 (secp256k1) Linked Data"
	ldpEcdsaSecp256k1Signature2019 = "EcdsaSecp256k1Signature2019 Linked Data"

	jwsProof = "Ed25519 JWS"
)

// SetContext is called before every scenario is run with a fresh new context.
func (s *SDKSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers Verifiable Credential steps.
func (s *SDKSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^"([^"]*)" issues credential at "([^"]*)" regarding "([^"]*)" to "([^"]*)" with "([^"]*)" proof$`, s.issueCredential) //nolint:lll
	gs.Step(`^"([^"]*)" receives the credential and verifies it$`, s.verifyCredential)
}

func (s *SDKSteps) issueCredential(issuer, issuedAt, subject, holder, proofType string) error {
	err := s.createDID(issuer, holder, proofType)
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

func (s *SDKSteps) addVCProof(vc *verifiable.Credential, issuer, proofType string) ([]byte, error) {
	doc := s.getPublicDID(issuer)
	pubKeyID := doc.VerificationMethod[0].ID

	cr := s.bddContext.AgentCtx[issuer].Crypto()
	cryptoSigner := newCryptoSigner(cr, s.bddContext.KeyHandles[issuer])
	secp256k1Signer := newSecp256k1Signer(s.secp256k1PrivKey)

	switch proofType {
	case ldpEd25519Signature2018:
		return s.getVCWithEd25519LDP(vc, cryptoSigner, pubKeyID)

	case ldpJSONWebSignatureECP256, ldpJSONWebSignatureEd25519, ldpJSONWebSignatureSecp256k1:
		return s.getVCWithJSONWebSignatureLDP(vc, proofType, secp256k1Signer, cryptoSigner, pubKeyID)

	case ldpEcdsaSecp256k1Signature2019:
		return s.getVCWithEcdsaSecp256k1Signature2019LDP(vc, secp256k1Signer, pubKeyID)

	case jwsProof:
		return s.getVCAsJWS(vc, cryptoSigner, pubKeyID)

	default:
		return nil, errors.New("unsupported proof type: " + proofType)
	}
}

func (s *SDKSteps) getVCAsJWS(vc *verifiable.Credential,
	cryptoSigner verifiable.Signer, pubKeyID string) ([]byte, error) {
	jwtClaims, err := vc.JWTClaims(false)
	if err != nil {
		return nil, err
	}

	jws, err := jwtClaims.MarshalJWS(verifiable.EdDSA, cryptoSigner, pubKeyID)
	if err != nil {
		return nil, err
	}

	return []byte(jws), nil
}

func (s *SDKSteps) getVCWithEcdsaSecp256k1Signature2019LDP(vc *verifiable.Credential,
	secp256k1Signer verifiable.Signer, pubKeyID string) ([]byte, error) {
	loader, err := CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "EcdsaSecp256k1Signature2019",
		Suite:                   ecdsasecp256k1signature2019.New(suite.WithSigner(secp256k1Signer)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &vc.Issued.Time,
		VerificationMethod:      pubKeyID,
	}, jsonld.WithDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	return vc.MarshalJSON()
}

func (s *SDKSteps) getVCWithJSONWebSignatureLDP(vc *verifiable.Credential, proofType string,
	secp256k1Signer, cryptoSigner verifiable.Signer, pubKeyID string) ([]byte, error) {
	var vcSuite signer.SignatureSuite

	if proofType == ldpJSONWebSignatureSecp256k1 {
		vcSuite = jsonwebsignature2020.New(suite.WithSigner(secp256k1Signer))
	} else {
		vcSuite = jsonwebsignature2020.New(suite.WithSigner(cryptoSigner))
	}

	loader, err := CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "JsonWebSignature2020",
		Suite:                   vcSuite,
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &vc.Issued.Time,
		VerificationMethod:      pubKeyID,
	}, jsonld.WithDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	return vc.MarshalJSON()
}

func (s *SDKSteps) getVCWithEd25519LDP(vc *verifiable.Credential,
	cryptoSigner verifiable.Signer, pubKeyID string) ([]byte, error) {
	loader, err := CreateDocumentLoader()
	if err != nil {
		return nil, err
	}

	err = vc.AddLinkedDataProof(&verifiable.LinkedDataProofContext{
		SignatureType:           "Ed25519Signature2018",
		Suite:                   ed25519signature2018.New(suite.WithSigner(cryptoSigner)),
		SignatureRepresentation: verifiable.SignatureJWS,
		Created:                 &vc.Issued.Time,
		VerificationMethod:      pubKeyID,
	}, jsonld.WithDocumentLoader(loader))
	if err != nil {
		return nil, err
	}

	return vc.MarshalJSON()
}

func (s *SDKSteps) verifyCredential(holder string) error {
	vdr := s.bddContext.AgentCtx[holder].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()

	localKMS, ok := s.bddContext.AgentCtx[holder].KMS().(*localkms.LocalKMS)
	if !ok {
		return errors.New("expected Local KMS")
	}

	verifier := suite.NewCryptoVerifier(newLocalCryptoVerifier(s.bddContext.AgentCtx[holder].Crypto(), localKMS))

	loader, err := CreateDocumentLoader()
	if err != nil {
		return err
	}

	parsedVC, err := verifiable.ParseCredential(s.issuedVCBytes,
		verifiable.WithPublicKeyFetcher(pKeyFetcher),
		verifiable.WithEmbeddedSignatureSuites(
			ed25519signature2018.New(suite.WithVerifier(verifier)),
			jsonwebsignature2020.New(suite.WithVerifier(jsonwebsignature2020.NewPublicKeyVerifier())),
			ecdsasecp256k1signature2019.New(suite.WithVerifier(ecdsasecp256k1signature2019.NewPublicKeyVerifier()))),
		verifiable.WithJSONLDDocumentLoader(loader))
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

func (s *SDKSteps) createDID(issuer, holder, proofType string) error {
	const (
		inboundHost     = "localhost"
		inboundPort     = "random"
		endpointURL     = "${SIDETREE_URL}"
		acceptDidMethod = "sidetree"
	)

	participants := issuer + "," + holder
	agentSDK := bddagent.NewSDKSteps()
	agentSDK.SetContext(s.bddContext)

	err := agentSDK.CreateAgentWithHTTPDIDResolver(participants, inboundHost, inboundPort, endpointURL, acceptDidMethod)
	if err != nil {
		return err
	}

	if err := s.createKeyPair(issuer, proofType); err != nil {
		return err
	}

	if err := didresolver.CreateDIDDocument(s.bddContext, participants, mapDIDKeyType(proofType)); err != nil {
		return err
	}

	didExchangeSDK := bddDIDExchange.NewDIDExchangeSDKSteps()
	didExchangeSDK.SetContext(s.bddContext)

	return didExchangeSDK.WaitForPublicDID(participants, 10)
}

func (s *SDKSteps) createKeyPair(agent, proofType string) error {
	// TODO A special case for Secp256k1 - Crypto/KMS does not support it for now
	//  (https://github.com/hyperledger/aries-framework-go/issues/1285)
	if proofType == ldpJSONWebSignatureSecp256k1 || proofType == ldpEcdsaSecp256k1Signature2019 {
		return s.createSecp256k1KeyPair(agent)
	}

	localKMS, ok := s.bddContext.AgentCtx[agent].KMS().(*localkms.LocalKMS)
	if !ok {
		return errors.New("expected LocalKMS type of KMS")
	}

	keyType := mapCryptoKeyType(proofType)

	kid, kh, err := localKMS.Create(keyType)
	if err != nil {
		return err
	}

	pubKeyBytes, err := localKMS.ExportPubKeyBytes(kid)
	if err != nil {
		return err
	}

	pubKeyJWK, err := createJWK(pubKeyBytes, keyType)
	if err != nil {
		return err
	}

	s.bddContext.PublicKeys[agent] = pubKeyJWK
	s.bddContext.KeyHandles[agent] = kh

	return nil
}

func (s *SDKSteps) createSecp256k1KeyPair(agent string) error {
	btcecPrivKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return err
	}

	ecdsaPrivKey := btcecPrivKey.ToECDSA()

	jwk, err := jose.JWKFromKey(&ecdsaPrivKey.PublicKey)
	if err != nil {
		return err
	}

	s.bddContext.PublicKeys[agent] = jwk
	s.secp256k1PrivKey = ecdsaPrivKey

	return nil
}

func createJWK(pubKeyBytes []byte, keyType kms.KeyType) (*jose.JWK, error) {
	var pubKey interface{}

	switch keyType {
	case kms.ED25519Type:
		pubKey = ed25519.PublicKey(pubKeyBytes)
	case kms.ECDSAP256TypeIEEEP1363:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes)
		pubKey = &ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
	default:
		return nil, errors.New("unsupported key type: " + string(keyType))
	}

	return jose.JWKFromKey(pubKey)
}

func mapCryptoKeyType(proofType string) kms.KeyType {
	switch proofType {
	case ldpEd25519Signature2018, ldpJSONWebSignatureEd25519, jwsProof:
		return kms.ED25519Type
	case ldpJSONWebSignatureECP256:
		return kms.ECDSAP256TypeIEEEP1363
	default:
		panic("unsupported proof type: " + proofType)
	}
}

func mapDIDKeyType(proofType string) string {
	switch proofType {
	case ldpEd25519Signature2018, jwsProof:
		return "Ed25519VerificationKey2018"
	case ldpJSONWebSignatureECP256, ldpJSONWebSignatureEd25519, ldpJSONWebSignatureSecp256k1:
		return "JsonWebKey2020"
	case ldpEcdsaSecp256k1Signature2019:
		return "EcdsaSecp256k1VerificationKey2019"
	default:
		panic("unsupported proof type: " + proofType)
	}
}

// CreateDocumentLoader creates a JSON-LD document loader with extra JSON-LD test contexts.
func CreateDocumentLoader() (ld.DocumentLoader, error) {
	loader, err := jld.NewDocumentLoader(mem.NewProvider(), jld.WithExtraContexts(bddjsonld.Contexts()...))
	if err != nil {
		return nil, fmt.Errorf("create document loader: %w", err)
	}

	return loader, nil
}
