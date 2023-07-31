package common

import afgjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"

type commonWrapper interface {
	VerifyDisclosuresInSDJWT(disclosures []string, signedJWT *afgjwt.JSONWebToken) error
	GetDisclosureClaims(disclosures []string) ([]*DisclosureClaim, error)
}

func newCommon(version SDJWTVersion) commonWrapper {
	if version == SDJWTVersionV5 {
		return newCommonV5()
	}

	return newCommonV2()
}
