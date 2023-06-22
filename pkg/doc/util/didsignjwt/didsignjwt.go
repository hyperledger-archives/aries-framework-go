/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didsignjwt

import (
	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/jwt/didsignjwt"
	"github.com/hyperledger/aries-framework-go/spi/vdr"
)

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

type cryptoSigner interface {
	// Sign will sign msg using a matching signature primitive in kh key handle of a private key
	// returns:
	// 		signature in []byte
	//		error in case of errors
	Sign(msg []byte, kh interface{}) ([]byte, error)
}

// A Signer is capable of signing data.
type Signer = didsignjwt.Signer

// SignerGetter creates a signer that signs with the private key corresponding to the given public key.
type SignerGetter = didsignjwt.SignerGetter

// UseDefaultSigner provides SignJWT with a signer that uses the given KMS and Crypto instances.
func UseDefaultSigner(r keyReader, s cryptoSigner) SignerGetter {
	return didsignjwt.UseDefaultSigner(r, s)
}

// SignJWT signs a JWT using a key in the given KMS, identified by an owned DID.
//
//	Args:
//		- Headers to include in the created JWT.
//		- Claims for the created JWT.
//		- The ID of the key to use for signing, as a DID, either with a fragment identifier to specify a verification
//		  method, or without, in which case the first Authentication or Assertion verification method is used.
//		- A SignerGetter that can provide a signer when given the key ID for the signing key.
//		- A VDR that can resolve the provided DID.
func SignJWT( // nolint: funlen,gocyclo
	headers,
	claims map[string]interface{},
	kid string,
	signerProvider SignerGetter,
	didResolver didResolver,
) (string, error) {
	return didsignjwt.SignJWT(headers, claims, kid, signerProvider, didResolver)
}

// VerifyJWT verifies a JWT that was signed with a DID.
//
// Args:
//   - JWT to verify.
//   - A VDR that can resolve the JWT's signing DID.
func VerifyJWT(compactJWT string,
	didResolver didResolver) error {
	return didsignjwt.VerifyJWT(compactJWT, didResolver)
}

// ResolveSigningVM resolves a DID KeyID using the given did resolver, and returns either:
//
//   - the Verification Method identified by the given key ID, or
//   - the first Assertion Method in the DID doc, if the DID provided has no fragment component.
//
// Returns:
//   - a verification method suitable for signing.
//   - the full DID#KID identifier of the returned verification method.
func ResolveSigningVM(kid string, didResolver didResolver) (*did.VerificationMethod, string, error) {
	return didsignjwt.ResolveSigningVM(kid, didResolver)
}
