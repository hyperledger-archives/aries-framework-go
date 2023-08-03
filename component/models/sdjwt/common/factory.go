/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
)

type commonWrapper interface {
	VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error
}

func newCommon(version SDJWTVersion) commonWrapper {
	if version == SDJWTVersionV5 {
		return newCommonV5()
	}

	return newCommonV2()
}
