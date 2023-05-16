/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resolver

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/kidresolver"
	"github.com/hyperledger/aries-framework-go/component/models/jose/diddocresolver"
)

const (
	jsonWebKey2020            = "JsonWebKey2020"
	x25519KeyAgreementKey2019 = "X25519KeyAgreementKey2019"
)

// KIDResolver helps resolve the kid public key from a recipient 'kid' or a sender 'skid' during JWE decryption.
// The JWEDecrypter should be able to load the public key using a resolution scheme for a key reference found in the
// 'skid' JWE protected header/'kid' recipient header.
type KIDResolver = kidresolver.KIDResolver

// DIDKeyResolver resolves a 'kid'/'skid' containing a did:key value.
type DIDKeyResolver = kidresolver.DIDKeyResolver

// StoreResolver resolves a 'kid'/'skid' containing a kms ID value (JWK fingerprint) from a dedicated pre-loaded store.
// Note: this is not a kms keystore. This StoreResolver is useful in cases where a thirdparty store is needed. This is
// useful in unit tests and especially for test vectors using the ECDH-1PU Appendix B example to load the sender key
// so that recipients can resolve a predefined 'skid'. Aries Framework Go is using the DIDKeyResolver by default (for
// request without DID docs) and DIDDocResolver (for requests with existing DID connections).
type StoreResolver = kidresolver.StoreResolver

// DIDDocResolver helps resolves a KMS kid from 'kid'/'skid' with values set as didDoc[].KeyAgreement[].ID. The list of
// DIDDocs should contain both sender and recipients docs for proper resolutio during unpacking.
type DIDDocResolver = diddocresolver.DIDDocResolver
