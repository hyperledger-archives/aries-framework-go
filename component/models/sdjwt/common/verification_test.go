/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	afjose "github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	afjwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
)

func TestVerifySigningAlgorithm(t *testing.T) {
	r := require.New(t)

	t.Run("success - EdDSA signing algorithm", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := VerifySigningAlg(headers, []string{"EdDSA"})
		r.NoError(err)
	})

	t.Run("error - signing algorithm can not be empty", func(t *testing.T) {
		headers := make(afjose.Headers)
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "missing alg")
	})

	t.Run("success - EdDSA signing algorithm not in allowed list", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "EdDSA"
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg 'EdDSA' is not in the allowed list")
	})

	t.Run("error - signing algorithm can not be none", func(t *testing.T) {
		headers := make(afjose.Headers)
		headers["alg"] = "none"
		err := VerifySigningAlg(headers, []string{"RS256"})
		r.Error(err)
		r.Contains(err.Error(), "alg value cannot be 'none'")
	})
}

func TestVerifyDisclosuresInSDJWT(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signer := afjwt.NewEd25519Signer(privKey)

	t.Run("success", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
		r.NoError(err)
	})

	t.Run("success V5", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
		r.NoError(err)
	})

	t.Run("success - complex struct(spec example 2b)", func(t *testing.T) {
		specExample2bPresentation := fmt.Sprintf("%s%s", specExample2bJWT, specExample2bDisclosures)

		sdJWT := ParseCombinedFormatForPresentation(specExample2bPresentation)

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(sdJWT.Disclosures, signedJWT)
		r.NoError(err)
	})

	t.Run("success - no selective disclosures(valid case)", func(t *testing.T) {
		jwtPayload := &payload{
			Issuer: "issuer",
			SDAlg:  "sha-256",
		}

		signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.NoError(err)
	})

	t.Run("success - selective disclosures nil", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload[SDAlgorithmKey] = testAlg
		payload[SDKey] = nil

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.NoError(err)
	})

	t.Run("error - disclosure not present in SD-JWT", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuance)
		require.Equal(t, 1, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalSDDisclosure), signedJWT)
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0' not found in SD-JWT disclosure digests")
	})

	t.Run("error - disclosure not present in SD-JWT without selective disclosures", func(t *testing.T) {
		jwtPayload := &payload{
			Issuer: "issuer",
			SDAlg:  testAlg,
		}

		signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT([]string{additionalSDDisclosure}, signedJWT)
		r.Error(err)
		r.Contains(err.Error(),
			"disclosure digest 'X9yH0Ajrdm1Oij4tWso9UzzKJvPoDxwmuEcO3XAdRC0' not found in SD-JWT disclosure digests")
	})

	t.Run("error - missing algorithm", func(t *testing.T) {
		jwtPayload := &payload{
			Issuer: "issuer",
		}

		signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be present in SD-JWT", SDAlgorithmKey)
	})

	t.Run("error - invalid algorithm", func(t *testing.T) {
		jwtPayload := payload{
			Issuer: "issuer",
			SDAlg:  "SHA-XXX",
		}

		signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg 'SHA-XXX' not supported")
	})

	t.Run("error - algorithm is not a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload[SDAlgorithmKey] = 18

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT(nil, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "_sd_alg must be a string")
	})

	t.Run("error - selective disclosures must be an array", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload[SDAlgorithmKey] = testAlg
		payload[SDKey] = "test"

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT([]string{additionalSDDisclosure}, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry type[string] is not an array")
	})

	t.Run("error - selective disclosures must be a string", func(t *testing.T) {
		payload := make(map[string]interface{})
		payload[SDAlgorithmKey] = testAlg
		payload[SDKey] = []float64{123}

		signedJWT, err := afjwt.NewSigned(payload, nil, signer)
		r.NoError(err)

		err = VerifyDisclosuresInSDJWT([]string{additionalSDDisclosure}, signedJWT)
		r.Error(err)
		r.Contains(err.Error(), "get disclosure digests: entry item type[float64] is not a string")
	})

	t.Run("error - array element associated disclosure is invalid", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		additionalDigest, err := GetHash(crypto.SHA256, additionalSDDisclosure)
		r.NoError(err)

		oldDigest := findAndReplaceArrayElementDigest(signedJWT.Payload, additionalDigest)

		updatedDisclosures := []string{additionalSDDisclosure}
		for _, d := range sdJWT.Disclosures {
			h, err := GetHash(crypto.SHA256, d) // nolint
			r.NoError(err)
			if h == oldDigest {
				continue
			}
			updatedDisclosures = append(updatedDisclosures, d)
		}

		err = VerifyDisclosuresInSDJWT(updatedDisclosures, signedJWT)
		r.ErrorContains(err, fmt.Sprintf("invald disclosure associated with array element digest %s", additionalDigest))
	})

	t.Run("error - array element was found more then once", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		additionalDigest, err := GetHash(crypto.SHA256, additionalArrayElementDisclosure)
		r.NoError(err)

		ok := findAndAppendArrayElementDigest(signedJWT.Payload, additionalDigest)
		r.True(ok)

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalArrayElementDisclosure), signedJWT)
		r.ErrorContains(err, fmt.Sprintf("digest '%s' has been included in more than one place", additionalDigest))
	})

	t.Run("error - sd element associated disclosure is invalid", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		additionalDigest, err := GetHash(crypto.SHA256, additionalArrayElementDisclosure)
		r.NoError(err)

		ok := findAndAppendSDElementDigest(signedJWT.Payload, additionalDigest)
		r.True(ok)

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalArrayElementDisclosure), signedJWT)
		r.ErrorContains(err, fmt.Sprintf("invald disclosure associated with sd element digest %s", additionalDigest))
	})

	t.Run("error - sd element was found more then once", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		additionalDigest, err := GetHash(crypto.SHA256, additionalSDDisclosure)
		r.NoError(err)

		ok := findAndAppendSDElementDigest(signedJWT.Payload, additionalDigest, additionalDigest)
		r.True(ok)

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalSDDisclosure), signedJWT)
		r.ErrorContains(err, fmt.Sprintf("digest '%s' has been included in more than one place", additionalDigest))
	})

	t.Run("error - claim name was found more then once", func(t *testing.T) {
		sdJWT := ParseCombinedFormatForIssuance(testCombinedFormatForIssuanceV5)
		require.Equal(t, 6, len(sdJWT.Disclosures))

		signedJWT, _, err := afjwt.Parse(sdJWT.SDJWT, afjwt.WithSignatureVerifier(&NoopSignatureVerifier{}))
		require.NoError(t, err)

		signedJWT.Payload["address"].(map[string]interface{})["locality"] = "some existing claim"

		err = VerifyDisclosuresInSDJWT(append(sdJWT.Disclosures, additionalSDDisclosure), signedJWT)
		r.ErrorContains(err, "claim name 'locality' already exists at the same level")
	})
}

func findAndAppendSDElementDigest(claimsMap map[string]interface{}, additionalDigest ...interface{}) bool {
	if digests, ok := claimsMap[SDKey]; ok {
		if d, ok := digests.([]interface{}); ok {
			claimsMap[SDKey] = append(d, additionalDigest...)
			return true
		}
	}

	for _, v := range claimsMap {
		switch t := v.(type) {
		case map[string]interface{}:
			if ok := findAndAppendSDElementDigest(t, additionalDigest...); ok {
				return ok
			}
		}
	}

	return false
}

func findAndReplaceArrayElementDigest(claimsMap map[string]interface{}, additionalDigest string) string {
	if digest, ok := claimsMap[ArrayElementDigestKey]; ok {
		claimsMap[ArrayElementDigestKey] = additionalDigest
		return digest.(string)
	}

	for _, v := range claimsMap {
		switch t := v.(type) {
		case map[string]interface{}:
			res := findAndReplaceArrayElementDigest(t, additionalDigest)
			if res == "" {
				continue
			}

			return res
		case []interface{}:
			for _, nv := range t {
				if mapped, ok := nv.(map[string]interface{}); ok {
					return findAndReplaceArrayElementDigest(mapped, additionalDigest)
				}
			}
		}
	}

	return ""
}

func findAndAppendArrayElementDigest(claimsMap map[string]interface{}, additionalDigest string) bool {
	for k, v := range claimsMap {
		switch t := v.(type) {
		case map[string]interface{}:
			if ok := findAndAppendArrayElementDigest(t, additionalDigest); ok {
				return true
			}
		case []interface{}:
			for _, nv := range t {
				if mapped, ok := nv.(map[string]interface{}); ok {
					if _, ok := mapped[ArrayElementDigestKey]; ok {
						updatedList := append(t, map[string]interface{}{
							ArrayElementDigestKey: additionalDigest,
						}, map[string]interface{}{
							ArrayElementDigestKey: additionalDigest,
						})

						claimsMap[k] = updatedList

						return true
					}

					return findAndAppendArrayElementDigest(mapped, additionalDigest)
				}
			}
		}
	}

	return false
}

func TestVerifyTyp(t *testing.T) {
	type args struct {
		joseHeaders afjose.Headers
		expectedTyp string
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				joseHeaders: afjose.Headers{
					afjose.HeaderType: "kb+jwt",
				},
				expectedTyp: "kb+jwt",
			},
			wantErr: false,
		},
		{
			name: "error - missed typ",
			args: args{
				joseHeaders: afjose.Headers{},
			},
			wantErr: true,
		},
		{
			name: "error - mismatch",
			args: args{
				joseHeaders: afjose.Headers{
					afjose.HeaderType: "vc-sd+jwt",
				},
				expectedTyp: "kb+jwt",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyTyp(tt.args.joseHeaders, tt.args.expectedTyp); (err != nil) != tt.wantErr {
				t.Errorf("VerifyTyp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyJWT(t *testing.T) {
	r := require.New(t)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	r.NoError(err)

	signer := afjwt.NewEd25519Signer(privKey)

	type args struct {
		getSignedJWT func() *afjwt.JSONWebToken
		leeway       time.Duration
	}

	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				getSignedJWT: func() *afjwt.JSONWebToken {
					jwtPayload := jwt.Claims{
						Issuer:   "issuer",
						Subject:  "subject",
						Audience: []string{"aud1"},
					}

					signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
					r.NoError(err)

					return signedJWT
				},
				leeway: time.Minute,
			},
			wantErr: false,
		},
		{
			name: "error invalid payload",
			args: args{
				getSignedJWT: func() *afjwt.JSONWebToken {
					jwtPayload := jwt.Claims{}

					signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
					r.NoError(err)

					signedJWT.Payload = map[string]interface{}{
						"iss": []string{"iss1"},
					}

					return signedJWT
				},
			},
			wantErr: true,
		},
		{
			name: "error exp invalid",
			args: args{
				getSignedJWT: func() *afjwt.JSONWebToken {
					exp := jwt.NumericDate(time.Now().Add(-time.Hour).Unix())
					jwtPayload := jwt.Claims{
						Issuer:   "issuer",
						Subject:  "subject",
						Audience: []string{"aud1"},
						Expiry:   &exp,
					}

					signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
					r.NoError(err)

					return signedJWT
				},
				leeway: time.Minute,
			},
			wantErr: true,
		},
		{
			name: "error iat invalid",
			args: args{
				getSignedJWT: func() *afjwt.JSONWebToken {
					iat := jwt.NumericDate(time.Now().Add(time.Hour).Unix())
					jwtPayload := jwt.Claims{
						Issuer:   "issuer",
						Subject:  "subject",
						Audience: []string{"aud1"},
						IssuedAt: &iat,
					}

					signedJWT, err := afjwt.NewSigned(jwtPayload, nil, signer)
					r.NoError(err)

					return signedJWT
				},
				leeway: time.Minute,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := VerifyJWT(tt.args.getSignedJWT(), tt.args.leeway); (err != nil) != tt.wantErr {
				t.Errorf("VerifyJWT() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
