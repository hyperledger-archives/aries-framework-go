/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	_ "embed" //nolint:gci // required for go:embed
	"encoding/json"
	"errors"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	mockprovider "github.com/hyperledger/aries-framework-go/pkg/mock/provider"
	"github.com/hyperledger/aries-framework-go/pkg/wallet"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

type credentialsQuery struct {
	raw       json.RawMessage
	queryType wallet.QueryType
	resolved  []*verifiable.Presentation
}

// SDKSteps is steps for universal wallet JSON-LD support.
type SDKSteps struct {
	bddContext              *context.BDDContext
	crypto                  string
	vcBytes                 map[string][]byte
	keyIds                  map[string]string
	query                   credentialsQuery
	token                   string
	wallet                  *wallet.Wallet
	walletProvider          *mockprovider.Provider
	getAllCredentialsResult map[string]json.RawMessage
}

// NewSDKSteps creates steps for universal wallet JSON-LD support.
func NewSDKSteps() *SDKSteps {
	return &SDKSteps{
		vcBytes:                 map[string][]byte{},
		keyIds:                  map[string]string{},
		getAllCredentialsResult: map[string]json.RawMessage{},
	}
}

const (
	ed25519Crypto   = "Ed25519"
	secp256r1Crypto = "ECDSA Secp256r1"
	secp384r1Crypto = "ECDSA Secp384r1"
)

// SetContext is called before every scenario is run with a fresh new context.
func (s *SDKSteps) SetContext(ctx *context.BDDContext) {
	s.bddContext = ctx
}

// RegisterSteps registers steps for VC and VP in JSON-LD format.
func (s *SDKSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^credentials crypto algorithm ""([^"]*)""$`, s.setCryptoAlgorithm)
	gs.Step(`^"([^"]*)" agent is running on "([^"]*)" port "([^"]*)" `+
		`with http-binding did resolver url "([^"]*)" which accepts did method "([^"]*)"$`, s.createAgent)
	gs.Step(`^"([^"]*)" creates wallet profile$`, s.createWalletProfile)
	gs.Step(`^"([^"]*)" opens wallet$`, s.openWallet)
	gs.Step(`^"([^"]*)" closes wallet$`, s.closeWallet)
	gs.Step(`^"([^"]*)" issues "([^"]*)" credentials at "([^"]*)" regarding "([^"]*)" to "([^"]*)"$`, s.issueCredential)
	gs.Step(`^"([^"]*)" adds credentials to the wallet issued by "([^"]*)"$`, s.addCredentialsToWallet)
	gs.Step(`^"([^"]*)" verifies credential issued by "([^"]*)"$`, s.holderVerifiesCredentialsFromIssuer)
	gs.Step(`^"([^"]*)" queries credentials issued by "([^"]*)" using "([^"]*)" query type$`, s.queryPresentations)
	gs.Step(`^"([^"]*)" queries "([^"]*)" credentials issued by "([^"]*)" using "([^"]*)" query type$`,
		s.queryPresentationWithFormat)
	gs.Step(`^"([^"]*)" resolves query$`, s.resolveCredentialsQuery)
	gs.Step(`^"([^"]*)" adds "([^"]*)" presentations proof$`, s.addResolvedPresentationProof)
	gs.Step(`^"([^"]*)" receives presentations `+
		`signed by "([^"]*)" and verifies it$`, s.receivePresentationsAndVerify)
	gs.Step(`^"([^"]*)" verifies presentations signed by "([^"]*)" with credentials issued by "([^"]*)"$`,
		s.receivePresentationsAndVerifyWithIssuer)
	gs.Step(`^"([^"]*)" receives credentials from presentation `+
		`signed by "([^"]*)" and verifies it$`, s.receiveCredentialsAndVerify)
	gs.Step(`^"([^"]*)" creates credentials at "([^"]*)" `+
		`regarding "([^"]*)" without proof$`, s.createUnsecuredCredential)
	gs.Step(`^"([^"]*)" issues "([^"]*)" credentials using the wallet$`, s.issueCredentialsUsingWallet)
	gs.Step(`^"([^"]*)" queries all credentials from "([^"]*)"$`, s.queryAllCredentials)
	gs.Step(`^"([^"]*)" receives "([^"]*)" credentials$`, s.checkGetAllAmount)
	gs.Step(`^"([^"]*)" verifies credentials issued by "([^"]*)"$`, s.verifyGetAllCredential)
}

func (s *SDKSteps) setCryptoAlgorithm(crypto string) error {
	s.crypto = crypto

	return nil
}

func (s *SDKSteps) createKeyPairLocalKMS(agent, crypto string) error {
	localKMS, ok := s.bddContext.AgentCtx[agent].KMS().(*localkms.LocalKMS)
	if !ok {
		return errors.New("expected LocalKMS type of KMS")
	}

	keyType := mapCryptoKeyType(crypto)

	kid, kh, err := localKMS.Create(keyType)
	if err != nil {
		return err
	}

	pubKeyBytes, _, err := localKMS.ExportPubKeyBytes(kid)
	if err != nil {
		return err
	}

	pubKeyJWK, err := jwksupport.PubKeyBytesToJWK(pubKeyBytes, keyType)
	if err != nil {
		return err
	}

	s.bddContext.PublicKeys[agent] = pubKeyJWK
	s.bddContext.KeyHandles[agent] = kh
	s.keyIds[agent] = kid

	return nil
}

func mapCryptoKeyType(crypto string) kms.KeyType {
	switch crypto {
	case ed25519Crypto:
		return kms.ED25519Type
	case secp256r1Crypto:
		return kms.ECDSAP256IEEEP1363
	case secp384r1Crypto:
		return kms.ECDSAP384IEEEP1363
	default:
		panic("unsupported crypto type: " + crypto)
	}
}

func mapCryptoJWSAlg(crypto string) verifiable.JWSAlgorithm {
	switch crypto {
	case ed25519Crypto:
		return verifiable.EdDSA
	case secp256r1Crypto:
		return verifiable.ECDSASecp256r1
	case secp384r1Crypto:
		return verifiable.ECDSASecp384r1
	default:
		panic("unsupported crypto type: " + crypto)
	}
}
