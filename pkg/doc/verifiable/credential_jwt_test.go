/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

type badParseJWTClaims struct{}

func (b badParseJWTClaims) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	return nil, errors.New("cannot parse JWT claims")
}

func (b badParseJWTClaims) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	return new(jwtVCClaim).VC, nil
}

type badParseJWTRawClaims struct{}

func (b badParseJWTRawClaims) UnmarshalClaims(rawJwt []byte) (*JWTCredClaims, error) {
	return new(JWTCredClaims), nil
}

func (b badParseJWTRawClaims) UnmarshalVCClaim(rawJwt []byte) (map[string]interface{}, error) {
	return nil, errors.New("cannot parse raw JWT claims")
}

func TestDecodeJWT(t *testing.T) {
	_, _, err := decodeCredJWT([]byte{}, &badParseJWTClaims{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse JWT claims")

	_, _, err = decodeCredJWT([]byte{}, &badParseJWTRawClaims{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "cannot parse raw JWT claims")
}
