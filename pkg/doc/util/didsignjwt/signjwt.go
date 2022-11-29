/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didsignjwt

import (
	"errors"
	"fmt"

	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/vmparse"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	"github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/kmssigner"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	ed25519VerificationKey2018 = "Ed25519VerificationKey2018"

	// number of sections in verification method.
	vmSectionCount = 2
)

func (k *kmsSigner) Sign(data []byte) ([]byte, error) {
	return k.Signer.Sign(data, k.KeyHandle)
}

func (k *kmsSigner) Alg() string {
	return kmssigner.KeyTypeToJWA(k.KeyType)
}

type keyReader interface {
	// Get key handle for the given keyID
	// Returns:
	//  - handle instance (to private key)
	//  - error if failure
	Get(keyID string) (interface{}, error)
}

type didResolver interface {
	Resolve(did string, opts ...vdr.DIDMethodOption) (*did.DocResolution, error)
}

type signer interface {
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

type kmsSigner struct {
	KeyType   kms.KeyType
	KeyHandle interface{}
	Signer    signer
}

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
	keyReader keyReader,
	signer signer,
	didResolver didResolver,
) (string, error) {
	vm, vmID, err := resolveSigningVM(kid, didResolver)
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

	keyHandle, err := keyReader.Get(kmsKID)
	if err != nil {
		return "", fmt.Errorf("fetching the signing key from the key manager: %w", err)
	}

	km := &kmsSigner{KeyType: keyType, KeyHandle: keyHandle, Signer: signer}

	if headers == nil {
		headers = map[string]interface{}{}
	}

	if claims == nil {
		claims = map[string]interface{}{}
	}

	headers[jose.HeaderType] = "JWT"
	headers[jose.HeaderAlgorithm] = km.Alg()
	headers["crv"] = crv
	headers[jose.HeaderKeyID] = vmID

	tok, err := jwt.NewSigned(claims, headers, getJWTSigner(km, km.Alg()))
	if err != nil {
		return "", fmt.Errorf("signing JWT: %w", err)
	}

	compact, err := tok.Serialize(false)
	if err != nil {
		return "", fmt.Errorf("serializing JWT: %w", err)
	}

	return compact, nil
}

// VerifyJWT verifies a JWT that was signed with a DID.
//
// Args:
//   - JWT to verify.
//   - A VDR that can resolve the JWT's signing DID.
func VerifyJWT(compactJWT string,
	didResolver vdr.Registry) error {
	_, err := jwt.Parse(compactJWT, jwt.WithSignatureVerifier(jwt.NewVerifier(
		jwt.KeyResolverFunc(verifiable.NewVDRKeyResolver(didResolver).PublicKeyFetcher())),
	))
	if err != nil {
		return fmt.Errorf("jwt verification failed: %w", err)
	}

	return nil
}

func resolveSigningVM(kid string, didResolver didResolver) (*did.VerificationMethod, string, error) {
	vmSplit := strings.Split(kid, "#")

	if len(vmSplit) > vmSectionCount {
		return nil, "", errors.New("invalid verification method format")
	}

	signingDID := vmSplit[0]

	docRes, err := didResolver.Resolve(signingDID)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve signing DID: %w", err)
	}

	if len(vmSplit) == 1 {
		// look for assertionmethod
		verificationMethods := docRes.DIDDocument.VerificationMethods(did.AssertionMethod)

		if len(verificationMethods[did.AssertionMethod]) > 0 {
			vm := verificationMethods[did.AssertionMethod][0].VerificationMethod

			return &vm, fullVMID(signingDID, vm.ID), nil
		}

		return nil, "", fmt.Errorf("DID provided has no assertion method to use as a default signing key")
	}

	vmID := vmSplit[vmSectionCount-1]

	for _, verifications := range docRes.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if isSigningKey(verification.Relationship) && vmIDFragmentOnly(verification.VerificationMethod.ID) == vmID {
				vm := verification.VerificationMethod
				return &vm, kid, nil
			}
		}
	}

	return nil, "", fmt.Errorf("did document has no verification method with given ID")
}

func fullVMID(did, vmID string) string {
	vmIDSplit := strings.Split(vmID, "#")

	if len(vmIDSplit) == 1 {
		return did + "#" + vmIDSplit[0]
	} else if len(vmIDSplit[0]) == 0 {
		return did + "#" + vmIDSplit[1]
	}

	return vmID
}

func vmIDFragmentOnly(vmID string) string {
	vmSplit := strings.Split(vmID, "#")
	if len(vmSplit) == 1 {
		return vmSplit[0]
	}

	return vmSplit[1]
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
