/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm

import "github.com/hyperledger/aries-framework-go/pkg/doc/presexch"

// hasAnyAlgorithmsOrProofTypes looks at the given Format object and determines if it has any algorithms or proof types
// listed.
func hasAnyAlgorithmsOrProofTypes(format presexch.Format) bool {
	if anyJWTTypeHasAlgs(format) || anyLDPTypeHasProofTypes(format) {
		return true
	}

	return false
}

func anyJWTTypeHasAlgs(format presexch.Format) bool {
	if hasAnyAlgs(format.Jwt) ||
		hasAnyAlgs(format.JwtVC) ||
		hasAnyAlgs(format.JwtVP) {
		return true
	}

	return false
}

func anyLDPTypeHasProofTypes(format presexch.Format) bool {
	if hasAnyProofTypes(format.Ldp) ||
		hasAnyProofTypes(format.LdpVC) ||
		hasAnyProofTypes(format.LdpVP) {
		return true
	}

	return false
}

func hasAnyAlgs(jwtType *presexch.JwtType) bool {
	if jwtType != nil && len(jwtType.Alg) > 0 {
		return true
	}

	return false
}

func hasAnyProofTypes(ldpType *presexch.LdpType) bool {
	if ldpType != nil && len(ldpType.ProofType) > 0 {
		return true
	}

	return false
}
