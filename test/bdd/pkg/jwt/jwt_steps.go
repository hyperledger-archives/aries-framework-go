/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	_ "embed" //nolint:gci // required for go:embed
	"errors"
	"fmt"
	"strings"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

// SDKSteps is steps for VC and VP in JWT format using client SDK.
type SDKSteps struct {
	crypto        string
	bddContext    *context.BDDContext
	issuedVCBytes []byte
	issuedVC      *verifiable.Credential
	issuedVPBytes []byte
}

// NewJWTSDKSteps creates steps for VC and VP in JWT format with SDK.
func NewJWTSDKSteps() *SDKSteps {
	return &SDKSteps{}
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

// RegisterSteps registers steps for VC and VP in JWT format.
func (s *SDKSteps) RegisterSteps(gs *godog.Suite) {
	gs.Step(`^crypto algorithm ""([^"]*)""$`, s.setCryptoAlgorithm)
	gs.Step(`^"([^"]*)" issues VC at "([^"]*)" regarding "([^"]*)" to "([^"]*)"$`, s.issueCredential)
	gs.Step(`^"([^"]*)" receives the VC and verifies it$`, s.verifyCredential)
	gs.Step(`^"([^"]*)" embeds the VC into VP$`, s.createPresentation)
	gs.Step(`^"([^"]*)" verifies VP$`, s.verifyPresentation)
}

func (s *SDKSteps) getSigner(agent string) verifiable.Signer {
	cr := s.bddContext.AgentCtx[agent].Crypto()
	return newCryptoSigner(cr, s.bddContext.KeyHandles[agent])
}

func (s *SDKSteps) createKeys(participants string) error {
	for _, agent := range strings.Split(participants, ",") {
		if err := s.createKeyPair(agent, s.crypto); err != nil {
			return err
		}
	}

	return nil
}

func (s *SDKSteps) createKeyPair(agent, crypto string) error {
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

	pubKeyJWK, err := createJWK(pubKeyBytes, keyType)
	if err != nil {
		return err
	}

	s.bddContext.PublicKeys[agent] = pubKeyJWK
	s.bddContext.KeyHandles[agent] = kh

	return nil
}

func (s *SDKSteps) setCryptoAlgorithm(crypto string) error {
	s.crypto = crypto

	return nil
}

func createJWK(pubKeyBytes []byte, keyType kms.KeyType) (*jwk.JWK, error) {
	var pubKey interface{}

	switch keyType {
	case kms.ECDSAP256TypeDER, kms.ECDSAP384TypeDER:
		pk, err := x509.ParsePKIXPublicKey(pubKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("parse ECDSA public key: %w", err)
		}

		ecdsaPubKey, ok := pk.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.New("unexpected type of ecdsa public key")
		}

		pubKey = ecdsaPubKey

	case kms.ED25519Type:
		pubKey = ed25519.PublicKey(pubKeyBytes)

	default:
		return nil, errors.New("unsupported key type: " + string(keyType))
	}

	return jwksupport.JWKFromKey(pubKey)
}

func mapCryptoKeyType(crypto string) kms.KeyType {
	switch crypto {
	case ed25519Crypto:
		return kms.ED25519Type
	case secp256r1Crypto:
		return kms.ECDSAP256TypeDER
	case secp384r1Crypto:
		return kms.ECDSAP384TypeDER
	default:
		panic("unsupported crypto type: " + crypto)
	}
}
