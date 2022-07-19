//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"encoding/json"
	"fmt"

	clapi "github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/cl/api"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
)

// CL Prover
type CLProver struct {
	masterSecret    *ursa.MasterSecret
	masterSecretStr string
}

// Creates a new instance of CL Prover with the provided privateKey.
func NewCLProver(key []byte) (*CLProver, error) {
	ms, err := ursa.MasterSecretFromJSON(key)
	if err != nil {
		return nil, fmt.Errorf("cl_prover: invalid master secret json: %w", err)
	}

	msJson, err := ms.ToJSON()
	if err != nil {
		return nil, err
	}
	m := struct {
		MS string `json:"ms"`
	}{}
	err = json.Unmarshal(msJson, &m)
	if err != nil {
		return nil, err
	}

	return &CLProver{
		masterSecret:    ms,
		masterSecretStr: m.MS,
	}, nil
}

func (s *CLProver) CreateCredentialRequest(
	credOffer *clapi.CredentialOffer, credDef *clapi.CredentialDefinition, proverId string,
) (*clapi.CredentialRequest, error) {
	credentialValues, err := BuildValues(map[string]interface{}{}, &s.masterSecretStr)
	if err != nil {
		return nil, err
	}
	defer credentialValues.Free()

	blindedCredSecret, err := ursa.BlindCredentialSecrets(
		credDef.CredPubKey, credDef.CredDefCorrectnessProof, credOffer.Nonce, credentialValues,
	)
	if err != nil {
		return nil, err
	}

	credReqNonce, err := ursa.NewNonce()
	if err != nil {
		return nil, err
	}

	return &clapi.CredentialRequest{
		BlindedCredentialSecrets: blindedCredSecret,
		Nonce:                    credReqNonce,
		ProverId:                 proverId,
	}, nil
}

func (s *CLProver) ProcessCredential(
	credential *clapi.Credential, credRequest *clapi.CredentialRequest, credDef *clapi.CredentialDefinition,
) error {
	credentialValues, err := BuildValues(credential.Values, &s.masterSecretStr)
	if err != nil {
		return err
	}
	defer credentialValues.Free()

	return credential.Signature.ProcessCredentialSignature(
		credentialValues,
		credential.SigProof,
		credRequest.BlindedCredentialSecrets.BlindingFactor,
		credDef.CredPubKey,
		credRequest.Nonce,
	)
}

func (s *CLProver) CreateProof(
	presentationRequest *clapi.PresentationRequest, credentials []*clapi.Credential, credDefs []*clapi.CredentialDefinition,
) (*clapi.Proof, error) {
	if len(presentationRequest.Items) != len(credentials) {
		return nil, fmt.Errorf("Not enough credentials provided to fulfill the presentsation request")
	}
	if len(presentationRequest.Items) != len(credDefs) {
		return nil, fmt.Errorf("Not enough credential definitions provided to fulfill the presentsation request")
	}
	subProofRequests := make([]*ursa.SubProofRequestHandle, len(presentationRequest.Items))
	for i, presentationRequest := range presentationRequest.Items {
		subProofBuilder, err := ursa.NewSubProofRequestBuilder()
		if err != nil {
			return nil, err
		}
		for _, revealedAttr := range presentationRequest.RevealedAttrs {
			err = subProofBuilder.AddRevealedAttr(revealedAttr)
			if err != nil {
				return nil, err
			}
		}

		for _, predicate := range presentationRequest.Predicates {
			err = subProofBuilder.AddPredicate(predicate.Attr, predicate.PType, predicate.Value)
			if err != nil {
				return nil, err
			}
		}

		subProofRequest, err := subProofBuilder.Finalize()
		if err != nil {
			return nil, err
		}

		subProofRequests[i] = subProofRequest
	}

	proofBuilder, err := ursa.NewProofBuilder()
	if err != nil {
		return nil, err
	}
	err = proofBuilder.AddCommonAttribute("master_secret")
	if err != nil {
		return nil, err
	}

	subProofs := make([]*clapi.SubProof, len(subProofRequests))
	for i, subProofRequest := range subProofRequests {
		cred := credentials[i]
		credDef := credDefs[i]

		credentialValues, err := BuildValues(cred.Values, &s.masterSecretStr)
		if err != nil {
			return nil, err
		}
		defer credentialValues.Free()

		schema, nonSchema, err := BuildSchema(credDef.Attrs)
		if err != nil {
			return nil, err
		}
		defer schema.Free()
		defer nonSchema.Free()

		err = proofBuilder.AddSubProofRequest(
			subProofRequest,
			schema,
			nonSchema,
			cred.Signature,
			credentialValues,
			credDef.CredPubKey,
		)
		if err != nil {
			return nil, err
		}

		subProofs[i] = &clapi.SubProof{
			SubProof: subProofRequest,
			Attrs:    credDef.Attrs,
		}
	}

	ursaProof, err := proofBuilder.Finalize(presentationRequest.Nonce)
	if err != nil {
		return nil, err
	}

	return &clapi.Proof{
		Proof:     ursaProof,
		SubProofs: subProofs,
	}, nil
}

func (s *CLProver) Free() error {
	err := s.masterSecret.Free()
	if err != nil {
		return err
	}
	return nil
}
