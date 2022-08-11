/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package jwt

import (
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	bddverifiable "github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
)

func (s *SDKSteps) createPresentation(holder string) error {
	doc := s.getPublicDID(holder)
	pubKeyID := doc.VerificationMethod[0].ID

	publicKeyJWK := s.bddContext.PublicKeys[holder]

	keyType, err := publicKeyJWK.KeyType()
	if err != nil {
		return err
	}

	jwsAlgo, err := verifiable.KeyTypeToJWSAlgo(keyType)
	if err != nil {
		return err
	}

	signer := s.getSigner(holder)

	vp, err := verifiable.NewPresentation(verifiable.WithCredentials(s.issuedVC))
	if err != nil {
		return fmt.Errorf("failed to build VP from VC: %w", err)
	}

	vp.Holder = doc.ID

	jwtClaims, err := vp.JWTClaims([]string{}, false)
	if err != nil {
		return fmt.Errorf("failed to create JWT claims of VP: %w", err)
	}

	jws, err := jwtClaims.MarshalJWS(jwsAlgo, signer, pubKeyID)
	if err != nil {
		return err
	}

	s.issuedVPBytes = []byte(jws)

	return nil
}

func (s *SDKSteps) verifyPresentation(holder string) error {
	vdr := s.bddContext.AgentCtx[holder].VDRegistry()
	pKeyFetcher := verifiable.NewVDRKeyResolver(vdr).PublicKeyFetcher()

	loader, err := bddverifiable.CreateDocumentLoader()
	if err != nil {
		return err
	}

	vp, err := verifiable.ParsePresentation(s.issuedVPBytes,
		verifiable.WithPresPublicKeyFetcher(pKeyFetcher),
		verifiable.WithPresJSONLDDocumentLoader(loader))
	if err != nil {
		return err
	}

	if vp == nil {
		return errors.New("received nil presentation")
	}

	return nil
}
