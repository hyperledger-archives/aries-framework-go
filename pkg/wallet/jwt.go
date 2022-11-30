/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/didsignjwt"
)

// SignJWT creates a JWT signed by the wallet's KMS using a key from an owned DID.
//
//	Args:
//		- auth token for unlocking kms.
//		- Headers to include in the created JWT.
//		- Claims for the created JWT.
//		- the ID of the key to use for signing, as a DID, either with a fragment identifier to specify a verification
//		  method, or without, in which case the first Authentication or Assertion verification method is used.
func (c *Wallet) SignJWT(authToken string, headers, claims map[string]interface{}, kid string) (string, error) {
	session, err := sessionManager().getSession(authToken)
	if err != nil {
		return "", wrapSessionError(err)
	}

	return didsignjwt.SignJWT(headers, claims, kid,
		didsignjwt.UseDefaultSigner(session.KeyManager, c.walletCrypto), c.vdr)
}

// VerifyJWT verifies a JWT signed by a DID;
//
// Args:
//   - JWT to verify.
func (c *Wallet) VerifyJWT(compactJWT string) error {
	return didsignjwt.VerifyJWT(compactJWT, c.vdr)
}
