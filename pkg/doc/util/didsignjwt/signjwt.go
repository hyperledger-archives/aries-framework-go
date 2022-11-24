/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didsignjwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/vmparse"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/kmssigner"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	jsonWebKey2020             = "JsonWebKey2020"
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

	// number of sections in verification method.
	vmSectionCount = 2
)

// SignJWT signs a JWT using a key in the given KMS, identified by an owned DID.
//
//	Args:
//		- Headers to include in the created JWT.
//		- Claims for the created JWT.
//		- The ID of the key to use for signing, as a DID, either with a fragment identifier to specify a verification
//		  method, or without, in which case the first Authentication or Assertion verification method is used.
//		- A KMS instance that holds the private key identified by the kid parameter.
//		- A crypto.Crypto instance that can sign using the given key.
//		- A VDR that can resolve the provided DID.
func SignJWT( // nolint: funlen,gocyclo
	headers,
	claims map[string]interface{},
	kid string,
	keyManager kms.KeyManager,
	cryptoHandler crypto.Crypto,
	didResolver vdr.Registry,
) (string, error) {
	vm, err := resolveSigningVM(kid, didResolver)
	if err != nil {
		return "", err
	}

	pkBytes, keyType, crv, err := vmparse.VMToBytesTypeCrv(vm)
	if err != nil {
		return "", fmt.Errorf("parsing verification method: %w", err)
	}

	kmsKID, err := jwkkid.CreateKID(pkBytes, keyType)
	if err != nil {
		return "", fmt.Errorf("determining the internal ID of the signing key: %w", err)
	}

	keyHandle, err := keyManager.Get(kmsKID)
	if err != nil {
		return "", fmt.Errorf("fetching the signing key from the key manager: %w", err)
	}

	km := &kmssigner.KMSSigner{KeyType: keyType, KeyHandle: keyHandle, Crypto: cryptoHandler, MultiMsg: false}

	// TODO: what fields should we add by default to the claim set?
	//  iirc we want the nbf/iat timestamp?

	var alg string

	if vm.Type == ed25519VerificationKey2018 {
		alg = "EdDSA"
	} else if vm.Type == jsonWebKey2020 {
		jwkKey := vm.JSONWebKey()
		alg = jwkKey.Algorithm
	}

	if headers == nil {
		headers = map[string]interface{}{}
	}

	if claims == nil {
		claims = map[string]interface{}{}
	}

	headers["typ"] = "JWT"
	headers["alg"] = alg
	headers["crv"] = crv
	headers["kid"] = kid

	tok, err := jwt.NewSigned(claims, headers, getJWTSigner(km, alg))
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	compact, err := tok.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serializing JWT: %w", err)
	}

	return compact, nil
}

func resolveSigningVM(kid string, didResolver vdr.Registry) (*did.VerificationMethod, error) {
	vmSplit := strings.Split(kid, "#")

	if len(vmSplit) > vmSectionCount {
		return nil, errors.New("invalid verification method format")
	}

	signingDID := vmSplit[0]

	docRes, err := didResolver.Resolve(signingDID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve signing DID: %w", err)
	}

	if len(vmSplit) == 1 {
		// look for assertionmethod
		verificationMethods := docRes.DIDDocument.VerificationMethods(did.AssertionMethod)

		if len(verificationMethods[did.AssertionMethod]) > 0 {
			vm := verificationMethods[did.AssertionMethod][0].VerificationMethod

			return &vm, nil
		}

		return nil, fmt.Errorf("DID provided has no assertion method to use as a default signing key")
	}

	vmID := vmSplit[vmSectionCount-1]

	for _, verifications := range docRes.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if isSigningKey(verification.Relationship) && strings.Contains(verification.VerificationMethod.ID, vmID) {
				vm := verification.VerificationMethod
				return &vm, nil
			}
		}
	}

	return nil, fmt.Errorf("did document has no verification method with given ID")
}

func isSigningKey(vr did.VerificationRelationship) bool {
	switch vr {
	case did.AssertionMethod, did.Authentication, did.VerificationRelationshipGeneral:
		return true
	}

	return false
}

type sign interface {
	Sign(data []byte) ([]byte, error)
	Alg() string
}

// jwtSigner implement jose.Signer interface.
type jwtSigner struct {
	signer  sign
	headers map[string]interface{}
}

func getJWTSigner(signer sign, algorithm string) *jwtSigner {
	headers := map[string]interface{}{
		jose.HeaderAlgorithm: algorithm,
	}

	return &jwtSigner{signer: signer, headers: headers}
}

func (s jwtSigner) Sign(data []byte) ([]byte, error) {
	return s.signer.Sign(data)
}

func (s jwtSigner) Headers() jose.Headers {
	return s.headers
}
