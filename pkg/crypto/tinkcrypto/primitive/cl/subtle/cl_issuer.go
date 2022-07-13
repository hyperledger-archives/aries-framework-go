//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"fmt"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// CL Issuer (Signer)
type CLIssuer struct {
	pubKey           *ursa.CredentialDefPubKey
	privKey          *ursa.CredentialDefPrivKey
	correctnessProof *ursa.CredentialDefKeyCorrectnessProof
	attrs            []string
}

// Creates a new instance of CLIssuer with the provided privateKey.
func NewCLIssuer(privKey []byte, pubKey []byte, correctnessProof []byte, attrs []string) (*CLIssuer, error) {
	clPubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	if err != nil {
		return nil, fmt.Errorf("cl_issuer: invalid cred def public key json: %w", err)
	}
	clPrivKey, err := ursa.CredentialPrivateKeyFromJSON(privKey)
	if err != nil {
		return nil, fmt.Errorf("cl_issuer: invalid cred def private key json: %w", err)
	}
	clCorrecrtnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	if err != nil {
		return nil, fmt.Errorf("cl_issuer: invalid cred def correctness proof json: %w", err)
	}

	return &CLIssuer{
		pubKey:           clPubKey,
		privKey:          clPrivKey,
		correctnessProof: clCorrecrtnessProof,
		attrs:            attrs,
	}, nil
}

func (s *CLIssuer) GetCredentialDefinition() (*clapi.CredentialDefinition, error) {
	return &clapi.CredentialDefinition{
		CredPubKey:              s.pubKey,
		CredDefCorrectnessProof: s.correctnessProof,
		Attrs:                   s.attrs,
	}, nil
}

func (s *CLIssuer) CreateCredentialOffer() (*clapi.CredentialOffer, error) {
	nonce, err := ursa.NewNonce()
	if err != nil {
		return nil, err
	}
	return &clapi.CredentialOffer{
		Nonce: nonce,
	}, nil
}

func (s *CLIssuer) IssueCredential(
	values map[string]interface{}, credentialRequest *clapi.CredentialRequest, credOffer *clapi.CredentialOffer,
) (*clapi.Credential, error) {
	credentialValues, err := BuildValues(values, nil)
	if err != nil {
		return nil, err
	}
	defer credentialValues.Free()

	signParams := ursa.NewSignatureParams()
	signParams.ProverID = credentialRequest.ProverId
	signParams.CredentialPubKey = s.pubKey
	signParams.CredentialPrivKey = s.privKey
	signParams.BlindedCredentialSecrets = credentialRequest.BlindedCredentialSecrets.Handle
	signParams.BlindedCredentialSecretsCorrectnessProof = credentialRequest.BlindedCredentialSecrets.CorrectnessProof
	signParams.CredentialNonce = credOffer.Nonce
	signParams.CredentialValues = credentialValues
	signParams.CredentialIssuanceNonce = credentialRequest.Nonce

	sig, sigCorrectnessProof, err := signParams.SignCredential()
	return &clapi.Credential{
		Signature: sig,
		SigProof:  sigCorrectnessProof,
		Values:    values,
	}, err
}

func (s *CLIssuer) Free() error {
	err := s.correctnessProof.Free()
	if err != nil {
		return err
	}
	err = s.privKey.Free()
	if err != nil {
		return err
	}
	err = s.pubKey.Free()
	if err != nil {
		return err
	}
	return nil
}
