//go:build ursa
// +build ursa

/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ursa

import (
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cl"
	"github.com/hyperledger/aries-framework-go/pkg/internal/ursautil"
)

// subProofItem is a auxiliary struct for processing proofs.
type subProofItem struct {
	BlindedVals          []byte
	Credential           *cl.Credential
	CredentialDefinition *cl.CredentialDefinition
	Item                 *cl.PresentationRequestItem
}

func newNonce() ([]byte, error) {
	_nonce, err := ursa.NewNonce()
	if err != nil {
		return nil, err
	}

	defer _nonce.Free() // nolint: errcheck

	nonce, err := _nonce.ToJSON()
	if err != nil {
		return nil, err
	}

	return nonce, nil
}

func blindCredentialSecrets(
	pubKey []byte,
	correctnessProof []byte,
	nonce []byte,
	blindedMs []byte,
) (*cl.BlindedCredentialSecrets, error) {
	_nonce, err := ursa.NonceFromJSON(string(nonce))
	if err != nil {
		return nil, err
	}

	defer _nonce.Free() // nolint: errcheck

	_pubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	if err != nil {
		return nil, err
	}

	defer _pubKey.Free() // nolint: errcheck

	_correctnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	if err != nil {
		return nil, err
	}

	defer _correctnessProof.Free() // nolint: errcheck

	_blindedMs, err := ursa.CredentialValuesFromJSON(blindedMs)
	if err != nil {
		return nil, err
	}

	defer _blindedMs.Free() // nolint: errcheck

	_blindedSecrets, err := ursa.BlindCredentialSecrets(_pubKey, _correctnessProof, _nonce, _blindedMs)
	if err != nil {
		return nil, err
	}

	defer _blindedSecrets.Handle.Free()           // nolint: errcheck
	defer _blindedSecrets.CorrectnessProof.Free() // nolint: errcheck
	defer _blindedSecrets.BlindingFactor.Free()   // nolint: errcheck

	secrets, err := _blindedSecrets.Handle.ToJSON()
	if err != nil {
		return nil, err
	}

	proof, err := _blindedSecrets.CorrectnessProof.ToJSON()
	if err != nil {
		return nil, err
	}

	blindingFactor, err := _blindedSecrets.BlindingFactor.ToJSON()
	if err != nil {
		return nil, err
	}

	return &cl.BlindedCredentialSecrets{Handle: secrets, CorrectnessProof: proof, BlindingFactor: blindingFactor}, nil
}

// nolint: funlen
func processCredentialSignature(
	credential *cl.Credential,
	credReq *cl.CredentialRequest,
	credDef *cl.CredentialDefinition,
	blindedVals []byte,
) error {
	_signature, err := ursa.CredentialSignatureFromJSON(credential.Signature)
	if err != nil {
		return err
	}

	defer _signature.Free() // nolint: errcheck

	_correctnessProof, err := ursa.CredentialSignatureCorrectnessProofFromJSON(credential.SigProof)
	if err != nil {
		return err
	}

	defer _correctnessProof.Free() // nolint: errcheck

	_blindingFactor, err := ursa.CredentialSecretsBlindingFactorsFromJSON(credReq.BlindedCredentialSecrets.BlindingFactor)
	if err != nil {
		return err
	}

	defer _blindingFactor.Free() // nolint: errcheck

	_nonce, err := ursa.NonceFromJSON(string(credReq.Nonce))
	if err != nil {
		return err
	}

	defer _nonce.Free() // nolint: errcheck

	_pubKey, err := ursa.CredentialPublicKeyFromJSON(credDef.CredPubKey)
	if err != nil {
		return err
	}

	defer _pubKey.Free() // nolint: errcheck

	_blindedVals, err := ursa.CredentialValuesFromJSON(blindedVals)
	if err != nil {
		return err
	}

	defer _blindedVals.Free() // nolint: errcheck

	err = _signature.ProcessCredentialSignature(
		_blindedVals,
		_correctnessProof,
		_blindingFactor,
		_pubKey,
		_nonce,
	)
	if err != nil {
		return err
	}

	updatedSignature, err := _signature.ToJSON()
	if err != nil {
		return err
	}

	updatedCorrectnessProof, err := _correctnessProof.ToJSON()
	if err != nil {
		return err
	}

	credential.Signature = updatedSignature
	credential.SigProof = updatedCorrectnessProof

	return nil
}

func createProof(
	items []*subProofItem,
	nonce []byte,
) ([]byte, error) {
	proofBuilder, err := ursa.NewProofBuilder()
	if err != nil {
		return nil, err
	}

	err = proofBuilder.AddCommonAttribute("master_secret")
	if err != nil {
		return nil, err
	}

	_reqNonce, err := ursa.NonceFromJSON(string(nonce))
	if err != nil {
		return nil, err
	}

	defer _reqNonce.Free() // nolint: errcheck

	for _, item := range items {
		err = processSubProof(proofBuilder, item)
		if err != nil {
			return nil, err
		}
	}

	_proof, err := proofBuilder.Finalize(_reqNonce)
	if err != nil {
		return nil, err
	}

	defer _proof.Free() // nolint: errcheck

	proofJSON, err := _proof.ToJSON()
	if err != nil {
		return nil, err
	}

	return proofJSON, nil
}

func processSubProof(
	proofBuilder *ursa.ProofBuilder,
	item *subProofItem,
) error {
	_request, err := buildSubProofRequest(item.Item.RevealedAttrs, item.Item.Predicates)
	if err != nil {
		return err
	}

	defer _request.Free() // nolint: errcheck

	_blindedValues, err := ursa.CredentialValuesFromJSON(item.BlindedVals)
	if err != nil {
		return err
	}

	defer _blindedValues.Free() // nolint: errcheck

	_signature, err := ursa.CredentialSignatureFromJSON(item.Credential.Signature)
	if err != nil {
		return err
	}

	defer _signature.Free() // nolint: errcheck

	_pubKey, err := ursa.CredentialPublicKeyFromJSON(item.CredentialDefinition.CredPubKey)
	if err != nil {
		return err
	}

	defer _pubKey.Free() // nolint: errcheck

	_schema, _nonSchema, err := ursautil.BuildSchema(item.CredentialDefinition.Attrs)
	if err != nil {
		return err
	}

	defer _schema.Free()    // nolint: errcheck
	defer _nonSchema.Free() // nolint: errcheck

	err = proofBuilder.AddSubProofRequest(
		_request,
		_schema,
		_nonSchema,
		_signature,
		_blindedValues,
		_pubKey,
	)

	return err
}

func verifyProof(
	proof *cl.Proof,
	items []*subProofItem,
	nonce []byte,
) error {
	verifier, err := ursa.NewProofVerifier()
	if err != nil {
		return err
	}

	_reqNonce, err := ursa.NonceFromJSON(string(nonce))
	if err != nil {
		return err
	}

	defer _reqNonce.Free() // nolint: errcheck

	_proof, err := ursa.ProofFromJSON(proof.Proof)
	if err != nil {
		return err
	}

	defer _proof.Free() // nolint: errcheck

	for _, item := range items {
		err = processSubProofVerifier(verifier, item)
		if err != nil {
			return err
		}
	}

	err = verifier.Verify(_proof, _reqNonce)

	return err
}

func processSubProofVerifier(
	verifier *ursa.ProofVerifier,
	item *subProofItem,
) error {
	_request, err := buildSubProofRequest(item.Item.RevealedAttrs, item.Item.Predicates)
	if err != nil {
		return err
	}

	defer _request.Free() // nolint: errcheck

	_pubKey, err := ursa.CredentialPublicKeyFromJSON(item.CredentialDefinition.CredPubKey)
	if err != nil {
		return err
	}

	defer _pubKey.Free() // nolint: errcheck

	_schema, _nonSchema, err := ursautil.BuildSchema(item.CredentialDefinition.Attrs)
	if err != nil {
		return err
	}

	defer _schema.Free()    // nolint: errcheck
	defer _nonSchema.Free() // nolint: errcheck

	err = verifier.AddSubProofRequest(
		_request,
		_schema,
		_nonSchema,
		_pubKey,
	)

	return err
}

func buildSubProofRequest(revealedAttrs []string, predicates []*cl.Predicate) (*ursa.SubProofRequestHandle, error) {
	subProofBuilder, err := ursa.NewSubProofRequestBuilder()
	if err != nil {
		return nil, err
	}

	for _, revealedAttr := range revealedAttrs {
		err = subProofBuilder.AddRevealedAttr(revealedAttr)
		if err != nil {
			return nil, err
		}
	}

	for _, predicate := range predicates {
		err = subProofBuilder.AddPredicate(predicate.Attr, predicate.PType, predicate.Value)
		if err != nil {
			return nil, err
		}
	}

	subProofRequest, err := subProofBuilder.Finalize()
	if err != nil {
		return nil, err
	}

	return subProofRequest, nil
}
