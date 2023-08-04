/*
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didsignjwt

import (
	"fmt"
	"strings"

	"github.com/hyperledger/aries-framework-go/component/models/did"
	"github.com/hyperledger/aries-framework-go/component/models/signature/verifier"
)

// PublicKeyFetcher fetches public key for JWT signing verification based on Issuer ID (possibly DID)
// and Key ID.
// If not defined, JWT encoding is not tested.
type PublicKeyFetcher func(issuerID, keyID string) (*verifier.PublicKey, error)

// VDRKeyResolver resolves DID in order to find public keys for VC verification using vdr.Registry.
// A source of DID could be issuer of VC or holder of VP. It can be also obtained from
// JWS "issuer" claim or "verificationMethod" of Linked Data Proof.
type VDRKeyResolver struct {
	vdr didResolver
}

// NewVDRKeyResolver creates VDRKeyResolver.
func NewVDRKeyResolver(vdr didResolver) *VDRKeyResolver {
	return &VDRKeyResolver{vdr: vdr}
}

func (r *VDRKeyResolver) resolvePublicKey(issuerDID, keyID string) (*verifier.PublicKey, error) {
	docResolution, err := r.vdr.Resolve(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("resolve DID %s: %w", issuerDID, err)
	}

	for _, verifications := range docResolution.DIDDocument.VerificationMethods() {
		for _, verification := range verifications {
			if strings.Contains(verification.VerificationMethod.ID, keyID) &&
				verification.Relationship != did.KeyAgreement {
				return &verifier.PublicKey{
					Type:  verification.VerificationMethod.Type,
					Value: verification.VerificationMethod.Value,
					JWK:   verification.VerificationMethod.JSONWebKey(),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("public key with KID %s is not found for DID %s", keyID, issuerDID)
}

// PublicKeyFetcher returns Public Key Fetcher via DID resolution mechanism.
func (r *VDRKeyResolver) PublicKeyFetcher() PublicKeyFetcher {
	return r.resolvePublicKey
}
