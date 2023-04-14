//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"fmt"

	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/internal/ursautil"
)

// CLSigner is used for CL signature using the provided CredDef key.
type CLSigner struct {
	pubKey           *ursa.CredentialDefPubKey
	privKey          *ursa.CredentialDefPrivKey
	correctnessProof *ursa.CredentialDefKeyCorrectnessProof
	attrs            []string
}

const (
	noncesSize = 2
)

// NewCLSigner creates a new instance of CLSigner with the provided privateKey.
func NewCLSigner(privKey, pubKey, correctnessProof []byte, attrs []string) (*CLSigner, error) {
	clPubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	if err != nil {
		return nil, fmt.Errorf("cl_signer: invalid cred def public key json: %w", err)
	}

	clPrivKey, err := ursa.CredentialPrivateKeyFromJSON(privKey)
	if err != nil {
		return nil, fmt.Errorf("cl_signer: invalid cred def private key json: %w", err)
	}

	clCorrecrtnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	if err != nil {
		return nil, fmt.Errorf("cl_signer: invalid cred def correctness proof json: %w", err)
	}

	return &CLSigner{
		pubKey:           clPubKey,
		privKey:          clPrivKey,
		correctnessProof: clCorrecrtnessProof,
		attrs:            attrs,
	}, nil
}

// GetCorrectnessProof will return correctness proof for a public key handle
// returns:
//
//	correctness proof in []byte
//	error in case of errors
func (s *CLSigner) GetCorrectnessProof() ([]byte, error) {
	correctnessProof, err := s.correctnessProof.ToJSON()
	if err != nil {
		return nil, err
	}

	return correctnessProof, nil
}

// Sign will generate a signature and related correctness proof
// for the provided values using secrets and related DID
// returns:
//
//	signature in []byte
//	correctness proof in []byte
//	error in case of errors
//
// nolint: funlen
func (s *CLSigner) Sign(
	values map[string]interface{},
	secrets []byte,
	correctnessProof []byte,
	nonces [][]byte,
	did string,
) ([]byte, []byte, error) {
	if len(nonces) < noncesSize {
		return nil, nil, fmt.Errorf("both Offer and Request nonces should be provided")
	}

	_credValues, err := ursautil.BuildValues(values, nil)
	if err != nil {
		return nil, nil, err
	}

	defer _credValues.Free() // nolint: errcheck

	_secrets, err := ursa.BlindedCredentialSecretsFromJSON(secrets)
	if err != nil {
		return nil, nil, err
	}

	defer _secrets.Free() // nolint: errcheck

	_correctnessProof, err := ursa.BlindedCredentialSecretsCorrectnessProofFromJSON(correctnessProof)
	if err != nil {
		return nil, nil, err
	}

	defer _correctnessProof.Free() // nolint: errcheck

	_offerNonce, err := ursa.NonceFromJSON(string(nonces[0]))
	if err != nil {
		return nil, nil, err
	}

	defer _offerNonce.Free() // nolint: errcheck

	_requestNonce, err := ursa.NonceFromJSON(string(nonces[1]))
	if err != nil {
		return nil, nil, err
	}

	defer _requestNonce.Free() // nolint: errcheck

	signParams := ursa.NewSignatureParams()
	signParams.ProverID = did
	signParams.CredentialPubKey = s.pubKey
	signParams.CredentialPrivKey = s.privKey
	signParams.BlindedCredentialSecrets = _secrets
	signParams.BlindedCredentialSecretsCorrectnessProof = _correctnessProof
	signParams.CredentialNonce = _offerNonce
	signParams.CredentialValues = _credValues
	signParams.CredentialIssuanceNonce = _requestNonce

	_signature, _sigCorrectnessProof, err := signParams.SignCredential()
	if err != nil {
		return nil, nil, err
	}

	defer _signature.Free()           // nolint: errcheck
	defer _sigCorrectnessProof.Free() // nolint: errcheck

	signature, err := _signature.ToJSON()
	if err != nil {
		return nil, nil, err
	}

	sigCorrectnessProof, err := _sigCorrectnessProof.ToJSON()
	if err != nil {
		return nil, nil, err
	}

	return signature, sigCorrectnessProof, nil
}

// Free ursa.CredDef ptrs.
func (s *CLSigner) Free() error {
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
