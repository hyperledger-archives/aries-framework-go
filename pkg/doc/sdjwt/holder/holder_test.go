/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package holder

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
)

const (
	testIssuer = "https://example.com/issuer"
	testAlg    = "sha-256"
)

func TestParse(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	r.NoError(e)

	signer := afjwt.NewEd25519Signer(privKey)
	claims := map[string]interface{}{"given_name": "Albert"}

	token, e := issuer.New(testIssuer, claims, nil, signer)
	r.NoError(e)
	sdJWTSerialized, e := token.Serialize(false)
	r.NoError(e)

	verifier, e := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(e)

	t.Run("success", func(t *testing.T) {
		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.NoError(err)
		require.NotNil(t, sdJWT)
		require.Equal(t, 1, len(sdJWT.Disclosures))
	})

	t.Run("success - with detached payload", func(t *testing.T) {
		jwsParts := strings.Split(sdJWTSerialized, ".")
		jwsDetached := fmt.Sprintf("%s..%s", jwsParts[0], jwsParts[2])

		jwsPayload, err := base64.RawURLEncoding.DecodeString(jwsParts[1])
		require.NoError(t, err)

		sdJWT, err := Parse(jwsDetached,
			WithSignatureVerifier(verifier), WithJWTDetachedPayload(jwsPayload))
		r.NoError(err)
		r.NotNil(r, sdJWT)
	})

	t.Run("error - invalid claims", func(t *testing.T) {
		// claims is not JSON
		sdJWTSerialized, err := buildJWS(signer, "not JSON")
		r.NoError(err)

		sdJWT, err := Parse(sdJWTSerialized, WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "read JWT claims from JWS payload")
		r.Nil(sdJWT)
	})
}

func TestWithJWTDetachedPayload(t *testing.T) {
	detachedPayloadOpt := WithJWTDetachedPayload([]byte("payload"))
	require.NotNil(t, detachedPayloadOpt)

	opts := &parseOpts{}
	detachedPayloadOpt(opts)
	require.Equal(t, []byte("payload"), opts.detachedPayload)
}

func TestVerifyDisclosuresInSDJWT(t *testing.T) {
	r := require.New(t)

	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signer := afjwt.NewEd25519Signer(privKey)

	verifier, err := afjwt.NewEd25519Verifier(pubKey)
	r.NoError(err)

	t.Run("success", func(t *testing.T) {
		claims := map[string]interface{}{"given_name": "Albert"}

		token, err := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(err)
		sdJWTSerialized, err := token.Serialize(false)
		r.NoError(err)

		sdJWT := common.ParseSDJWT(sdJWTSerialized)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		err = VerifyDisclosuresInSDJWT(sdJWT.Disclosures, sdJWT.JWTSerialized, afjwt.WithSignatureVerifier(verifier))
		r.NoError(err)
	})
	t.Run("success - no selective disclosures(valid case)", func(t *testing.T) {
		payload := &common.Payload{
			Issuer: "issuer",
			SDAlg:  "sha-256",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.NoError(err)
	})

	t.Run("success - selective disclosures nil", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = nil

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.NoError(err)
	})

	t.Run("error - disclosure not present in SD-JWT", func(t *testing.T) {
		claims := map[string]interface{}{"given_name": "Albert"}

		token, err := issuer.New(testIssuer, claims, nil, signer)
		r.NoError(err)
		sdJWTSerialized, err := token.Serialize(false)
		r.NoError(err)

		sdJWT := common.ParseSDJWT(sdJWTSerialized)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalDisclosure),
			sdJWT.JWTSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' not found in SD-JWT disclosure digests")
	})

	t.Run("error - disclosure not present in SD-JWT without selective disclosures", func(t *testing.T) {
		payload := &common.Payload{
			Issuer: "issuer",
			SDAlg:  testAlg,
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT([]string{additionalDisclosure}, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'qqvcqnczAMgYx7EykI6wwtspyvyvK790ge7MBbQ-Nus' not found in SD-JWT disclosure digests")
	})

	t.Run("error - invalid claims", func(t *testing.T) {
		// claims is not JSON
		jwtSerialized, err := buildJWS(signer, "not JSON")
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(),
			"read JWT claims from JWS payload: convert to map: json: cannot unmarshal string")
	})

	t.Run("error - missing algorithm", func(t *testing.T) {
		payload := &common.Payload{
			Issuer: "issuer",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT")
	})

	t.Run("error - invalid algorithm", func(t *testing.T) {
		payload := &common.Payload{
			Issuer: "issuer",
			SDAlg:  "SHA-XXX",
		}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg 'SHA-XXX 'not supported")
	})

	t.Run("error - algorithm is not a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = 18

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be a string")
	})

	t.Run("error - selective disclosures must be an array", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = "test"

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry type[string] is not an array")
	})

	t.Run("error - selective disclosures must be a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload["_sd_alg"] = testAlg
		payload["_sd"] = []int{123}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		jwtSerialized, err := signedJWT.Serialize(false)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, jwtSerialized, afjwt.WithSignatureVerifier(verifier))
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry item type[float64] is not a string")
	})
}

func buildJWS(signer jose.Signer, claims interface{}) (string, error) {
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	jws, err := jose.NewJWS(nil, nil, claimsBytes, signer)
	if err != nil {
		return "", err
	}

	return jws.SerializeCompact(false)
}

const additionalDisclosure = `WyIzanFjYjY3ejl3a3MwOHp3aUs3RXlRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd`
