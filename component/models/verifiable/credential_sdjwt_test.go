/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sort"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose"
	"github.com/hyperledger/aries-framework-go/spi/kms"

	afgojwt "github.com/hyperledger/aries-framework-go/component/models/jwt"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/component/models/sdjwt/holder"
)

func TestParseSDJWT(t *testing.T) {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sdJWTString, issuerID := createTestSDJWTCred(t, privKey)

	t.Run("success", func(t *testing.T) {
		newVC, e := ParseCredential([]byte(sdJWTString),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, pubKey, issuerID)))
		require.NoError(t, e)
		require.NotNil(t, newVC)
	})

	t.Run("success with SD JWT Version 5", func(t *testing.T) {
		sdJWTCredFormatString, issuerCredFormatID := createTestSDJWTCred(t, privKey,
			MakeSDJWTWithVersion(common.SDJWTVersionV5))

		newVC, e := ParseCredential([]byte(sdJWTCredFormatString),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, pubKey, issuerCredFormatID)))
		require.NoError(t, e)
		require.NotNil(t, newVC)
	})

	t.Run("success with sd alg in subject", func(t *testing.T) {
		vc, e := ParseCredential([]byte(sdJWTString), WithDisabledProofCheck())
		require.NoError(t, e)

		claims, e := vc.JWTClaims(false)
		require.NoError(t, e)

		claims.VC["credentialSubject"].(map[string]interface{})["_sd_alg"] = claims.VC["_sd_alg"]
		delete(claims.VC, "_sd_alg")

		ed25519Signer, e := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, e)

		vc.JWT, e = claims.MarshalJWS(EdDSA, ed25519Signer, issuerID+"#keys-1")
		require.NoError(t, e)

		modifiedCred, e := vc.MarshalWithDisclosure(DiscloseAll())
		require.NoError(t, e)

		newVC, e := ParseCredential([]byte(modifiedCred),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), issuerID)))
		require.NoError(t, e)
		require.NotNil(t, newVC)
	})

	t.Run("success with sd alg in subject and v5", func(t *testing.T) {
		vc, e := ParseCredential([]byte(sdJWTString), WithDisabledProofCheck())
		require.NoError(t, e)

		claims, e := vc.JWTClaims(false)
		require.NoError(t, e)

		claims.VC["credentialSubject"].(map[string]interface{})["_sd_alg"] = claims.VC["_sd_alg"]
		delete(claims.VC, "_sd_alg")

		ed25519Signer, e := newCryptoSigner(kms.ED25519Type)
		require.NoError(t, e)

		vc.JWT, e = claims.MarshalJWS(EdDSA, ed25519Signer, issuerID+"#keys-1")
		require.NoError(t, e)

		vc.SDJWTVersion = 100500
		modifiedCred, e := vc.MarshalWithDisclosure(DiscloseAll(), MarshalWithSDJWTVersion(common.SDJWTVersionV5))
		require.NoError(t, e)

		newVC, e := ParseCredential([]byte(modifiedCred),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), issuerID)))
		require.NoError(t, e)
		require.NotNil(t, newVC)
	})

	t.Run("success with mock holder binding", func(t *testing.T) {
		mockHolderBinding := "e30.e30.mockHolderBinding"

		newVC, e := ParseCredential([]byte(sdJWTString+common.CombinedFormatSeparator+mockHolderBinding),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, pubKey, issuerID)))
		require.NoError(t, e)
		require.Equal(t, mockHolderBinding, newVC.SDHolderBinding)
	})

	t.Run("invalid SDJWT disclosures", func(t *testing.T) {
		sdJWTWithUnknownDisclosure := sdJWTString +
			common.CombinedFormatSeparator + base64.RawURLEncoding.EncodeToString([]byte("blah blah"))

		newVC, e := ParseCredential([]byte(sdJWTWithUnknownDisclosure), WithDisabledProofCheck())
		require.Error(t, e)
		require.Nil(t, newVC)
		require.Contains(t, e.Error(), "invalid SDJWT disclosures")
	})
}

func TestMarshalWithDisclosure(t *testing.T) {
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sourceCred, _ := createTestSDJWTCred(t, privKey)

	t.Run("success", func(t *testing.T) {
		newVC, e2 := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
		require.NoError(t, e2)

		t.Run("disclose all with holder binding", func(t *testing.T) {
			_, privKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			var iat jwt.NumericDate = 0

			resultCred, err := newVC.MarshalWithDisclosure(DiscloseAll(), DisclosureHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    "abc123",
					Audience: "foo",
					IssuedAt: &iat,
				},
				Signer: afgojwt.NewEd25519Signer(privKey),
			}))
			require.NoError(t, err)

			src := common.ParseCombinedFormatForPresentation(sourceCred + common.CombinedFormatSeparator)
			res := common.ParseCombinedFormatForPresentation(resultCred)

			require.Equal(t, src.SDJWT, res.SDJWT)

			sort.Slice(src.Disclosures, func(i, j int) bool {
				return src.Disclosures[i] < src.Disclosures[j]
			})

			sort.Slice(res.Disclosures, func(i, j int) bool {
				return res.Disclosures[i] < res.Disclosures[j]
			})

			require.Equal(t, src.Disclosures, res.Disclosures)
			require.NotEmpty(t, res.HolderVerification)
		})

		t.Run("disclose required and some if-available claims", func(t *testing.T) {
			resultCred, err := newVC.MarshalWithDisclosure(
				DiscloseGivenRequired([]string{"type"}),
				DiscloseGivenIfAvailable([]string{"university", "favourite-animal"}))
			require.NoError(t, err)

			res := common.ParseCombinedFormatForPresentation(resultCred)
			require.Len(t, res.Disclosures, 2)
		})

		t.Run("disclose selected claims by creating SD-JWT from vc", func(t *testing.T) {
			_, privKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			vc, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			var iat jwt.NumericDate = 0

			resultCred, err := vc.MarshalWithDisclosure(
				DiscloseGivenRequired([]string{"university"}),
				DisclosureSigner(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1"),
				DisclosureHolderBinding(&holder.BindingInfo{
					Payload: holder.BindingPayload{
						Nonce:    "abc123",
						Audience: "foo",
						IssuedAt: &iat,
					},
					Signer: afgojwt.NewEd25519Signer(privKey),
				}))
			require.NoError(t, err)

			res := common.ParseCombinedFormatForPresentation(resultCred)
			require.Len(t, res.Disclosures, 1)
			require.NotEmpty(t, res.HolderVerification)
		})
	})

	t.Run("failure", func(t *testing.T) {
		newVC, e2 := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
		require.NoError(t, e2)

		t.Run("incompatible options", func(t *testing.T) {
			resultCred, err := newVC.MarshalWithDisclosure(
				DiscloseAll(),
				DiscloseGivenIfAvailable([]string{"university", "favourite-animal"}))
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.Contains(t, err.Error(), "incompatible options provided")

			resultCred, err = newVC.MarshalWithDisclosure(
				DiscloseGivenRequired([]string{"id"}),
				DiscloseAll())
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.Contains(t, err.Error(), "incompatible options provided")
		})

		t.Run("missing required claim", func(t *testing.T) {
			t.Run("not in disclosure list", func(t *testing.T) {
				resultCred, err := newVC.MarshalWithDisclosure(DiscloseGivenRequired([]string{"favourite-animal"}))
				require.Error(t, err)
				require.Empty(t, resultCred)
				require.Contains(t, err.Error(), "disclosure list missing required claim")
			})

			t.Run("disclosure list empty", func(t *testing.T) {
				badVC, err := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
				require.NoError(t, err)

				// disclosure list empty
				badVC.SDJWTDisclosures = nil

				resultCred, err := badVC.MarshalWithDisclosure(DiscloseGivenRequired([]string{"id"}))
				require.Error(t, err)
				require.Empty(t, resultCred)
				require.Contains(t, err.Error(), "disclosure list missing required claim")
			})

			t.Run("created sdjwt but claim not in VC", func(t *testing.T) {
				_, privKey, err := ed25519.GenerateKey(rand.Reader)
				require.NoError(t, err)

				vc, err := parseTestCredential(t, []byte(jwtTestCredential))
				require.NoError(t, err)

				resultCred, err := vc.MarshalWithDisclosure(
					DiscloseGivenRequired([]string{"favourite-animal"}),
					DisclosureSigner(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1"),
				)
				require.Error(t, err)
				require.Empty(t, resultCred)
				require.Contains(t, err.Error(), "disclosure list missing required claim")
			})
		})

		t.Run("holder binding error", func(t *testing.T) {
			expectErr := fmt.Errorf("expected error")

			resultCred, err := newVC.MarshalWithDisclosure(DiscloseAll(), DisclosureHolderBinding(&holder.BindingInfo{
				Payload: holder.BindingPayload{
					Nonce:    "abc123",
					Audience: "foo",
				},
				Signer: &mockSigner{signErr: expectErr},
			}))
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.ErrorIs(t, err, expectErr)
			require.Contains(t, err.Error(), "failed to create holder binding")
		})

		t.Run("missing signer when creating fresh SD-JWT credential", func(t *testing.T) {
			vc, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			resultCred, err := vc.MarshalWithDisclosure(DiscloseAll())
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.Contains(t, err.Error(), "credential needs signer")
		})

		t.Run("signer error creating fresh SD-JWT credential", func(t *testing.T) {
			expectErr := fmt.Errorf("expected error")

			vc, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			resultCred, err := vc.MarshalWithDisclosure(
				DiscloseAll(),
				DisclosureSigner(&mockSigner{signErr: expectErr}, ""))
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.ErrorIs(t, err, expectErr)
			require.Contains(t, err.Error(), "creating SD-JWT from Credential")
		})

		t.Run("holder binding error - when creating fresh SD-JWT credential", func(t *testing.T) {
			expectErr := fmt.Errorf("expected error")
			_, privKey, err := ed25519.GenerateKey(rand.Reader)
			require.NoError(t, err)

			vc, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			resultCred, err := vc.MarshalWithDisclosure(
				DiscloseAll(),
				DisclosureSigner(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1"),
				DisclosureHolderBinding(&holder.BindingInfo{
					Payload: holder.BindingPayload{
						Nonce:    "abc123",
						Audience: "foo",
					},
					Signer: &mockSigner{signErr: expectErr},
				}))
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.ErrorIs(t, err, expectErr)
			require.Contains(t, err.Error(), "create SD-JWT presentation")
		})
	})
}

func TestMakeSDJWT(t *testing.T) {
	pubKey, privKey, e := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, e)

	testCred := []byte(jwtTestCredential)

	vc, e := parseTestCredential(t, testCred)
	require.NoError(t, e)

	t.Run("success", func(t *testing.T) {
		t.Run("with default hash", func(t *testing.T) {
			sdjwt, err := vc.MakeSDJWT(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1")
			require.NoError(t, err)

			_, err = ParseCredential([]byte(sdjwt), WithPublicKeyFetcher(holderPublicKeyFetcher(pubKey)))
			require.NoError(t, err)
		})

		t.Run("with SD JWT V5", func(t *testing.T) {
			originalVersion := vc.SDJWTVersion
			vc.SDJWTVersion = common.SDJWTVersionDefault
			defer func() {
				vc.SDJWTVersion = originalVersion
			}()

			sdjwt, err := vc.MakeSDJWT(
				afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1",
				MakeSDJWTWithVersion(common.SDJWTVersionV5),
				MakeSDJWTWithRecursiveClaimsObjects([]string{"degree"}),
				MakeSDJWTWithAlwaysIncludeObjects([]string{"degree"}),
			)
			require.NoError(t, err)

			_, err = ParseCredential([]byte(sdjwt), WithPublicKeyFetcher(holderPublicKeyFetcher(pubKey)))
			require.NoError(t, err)
		})

		t.Run("with hash option", func(t *testing.T) {
			sdjwt, err := vc.MakeSDJWT(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1",
				MakeSDJWTWithHash(crypto.SHA512))
			require.NoError(t, err)

			_, err = ParseCredential([]byte(sdjwt), WithPublicKeyFetcher(holderPublicKeyFetcher(pubKey)))
			require.NoError(t, err)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("prepare claims", func(t *testing.T) {
			badVC := &Credential{}

			sdjwt, err := badVC.MakeSDJWT(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1")
			require.Error(t, err)
			require.Empty(t, sdjwt)
			require.Contains(t, err.Error(), "constructing VC JWT claims")
		})

		t.Run("creating SD-JWT", func(t *testing.T) {
			expectErr := fmt.Errorf("expected error")

			sdjwt, err := vc.MakeSDJWT(&mockSigner{signErr: expectErr}, "did:example:abc123#key-1")
			require.Error(t, err)
			require.Empty(t, sdjwt)
			require.ErrorIs(t, err, expectErr)
			require.Contains(t, err.Error(), "creating SD-JWT from VC")
		})
	})
}

func TestOptions(t *testing.T) {
	opts := []MakeSDJWTOption{
		MakeSDJWTWithRecursiveClaimsObjects([]string{"aa", "bb"}),
		MakeSDJWTWithAlwaysIncludeObjects([]string{"cc", "dd"}),
		MakeSDJWTWithNonSelectivelyDisclosableClaims([]string{"xx", "yy"}),
		MakeSDJWTWithVersion(100500),
	}

	opt := &MakeSDJWTOpts{}
	for _, o := range opts {
		o(opt)
	}

	assert.Equal(t, []string{"aa", "bb"}, opt.GetRecursiveClaimsObject())
	assert.Equal(t, []string{"cc", "dd"}, opt.GetAlwaysIncludeObject())
	assert.Equal(t, []string{"xx", "yy"}, opt.GetNonSDClaims())
	assert.Equal(t, common.SDJWTVersion(100500), opt.version)
}

func TestCreateDisplayCredential(t *testing.T) {
	ed25519Signer, e := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, e)

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sourceCred, _ := createTestSDJWTCred(t, privKey)

	t.Run("success", func(t *testing.T) {
		vc, e2 := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
		require.NoError(t, e2)

		t.Run("not a SD-JWT credential", func(t *testing.T) {
			vc2, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			displayVC, err := vc2.CreateDisplayCredential(DisplayAllDisclosures())
			require.NoError(t, err)
			require.Equal(t, vc2, displayVC)
		})

		t.Run("display all claims", func(t *testing.T) {
			displayVC, err := vc.CreateDisplayCredential(DisplayAllDisclosures())
			require.NoError(t, err)

			subj, ok := displayVC.Subject.([]Subject)
			require.True(t, ok)

			require.Len(t, subj, 1)
			require.NotEmpty(t, subj[0].ID)

			expectedFields := CustomFields{"degree": map[string]interface{}{
				"type":       "BachelorDegree",
				"university": "MIT",
			}}
			require.Equal(t, expectedFields, subj[0].CustomFields)
		})

		t.Run("not a SD-JWT credential map", func(t *testing.T) {
			vc2, err := parseTestCredential(t, []byte(jwtTestCredential))
			require.NoError(t, err)

			displayVC, err := vc2.CreateDisplayCredentialMap(DisplayAllDisclosures())
			require.NoError(t, err)
			require.NotEmpty(t, displayVC)
		})

		t.Run("display all claims map", func(t *testing.T) {
			displayVC, err := vc.CreateDisplayCredentialMap(DisplayAllDisclosures())
			require.NoError(t, err)
			require.NotEmpty(t, displayVC)
		})

		t.Run("display no claims", func(t *testing.T) {
			displayVC, err := vc.CreateDisplayCredential()
			require.NoError(t, err)

			subj, ok := displayVC.Subject.([]Subject)
			require.True(t, ok)

			require.Len(t, subj, 1)
			require.NotEmpty(t, subj[0].ID)
			require.Empty(t, subj[0].CustomFields)
		})

		t.Run("display subset of claims", func(t *testing.T) {
			displayVC, err := vc.CreateDisplayCredential(DisplayGivenDisclosures([]string{"id", "type"}))
			require.NoError(t, err)

			subj, ok := displayVC.Subject.([]Subject)
			require.True(t, ok)

			require.Len(t, subj, 1)
			require.NotEmpty(t, subj[0].ID)

			expectedFields := CustomFields{"degree": map[string]interface{}{
				"type": "BachelorDegree",
			}}
			require.Equal(t, expectedFields, subj[0].CustomFields)
		})
	})

	t.Run("failure", func(t *testing.T) {
		t.Run("incompatible options", func(t *testing.T) {
			vc, err := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
			require.NoError(t, err)

			displayVC, err := vc.CreateDisplayCredential(
				DisplayAllDisclosures(),
				DisplayGivenDisclosures([]string{"name"}),
			)
			require.Error(t, err)
			require.Nil(t, displayVC)
			require.Contains(t, err.Error(), "incompatible options provided")
		})

		t.Run("parsing malformed JWT VC", func(t *testing.T) {
			badVC := &Credential{
				JWT:          "blah blah blahblah blah",
				SDJWTHashAlg: "blah, blahblah",
			}

			displayVC, err := badVC.CreateDisplayCredential(DisplayAllDisclosures())
			require.Error(t, err)
			require.Nil(t, displayVC)
			require.Contains(t, err.Error(), "unmarshal VC JWT claims")
		})

		t.Run("adding claims back to VC", func(t *testing.T) {
			vc, err := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
			require.NoError(t, err)

			subj, ok := vc.Subject.([]Subject)
			require.True(t, ok)
			require.Len(t, subj, 1)

			testCases := []interface{}{
				"foo",                   // sd field not slice
				[]interface{}{"foo", 5}, // not all elements are strings
			}

			for _, testCase := range testCases {
				subj[0].CustomFields["_sd"] = testCase

				claims, err := vc.JWTClaims(false)
				require.NoError(t, err)

				badJWS, err := claims.MarshalJWS(EdDSA, ed25519Signer, "did:foo:bar#key-1")
				require.NoError(t, err)

				vc.JWT = badJWS

				displayVC, err := vc.CreateDisplayCredential(DisplayAllDisclosures())
				require.Error(t, err)
				require.Nil(t, displayVC)
				require.Contains(t, err.Error(), "assembling disclosed claims into vc")
			}
		})

		t.Run("result credential invalid", func(t *testing.T) {
			vc, err := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
			require.NoError(t, err)

			claims, err := vc.JWTClaims(false)
			require.NoError(t, err)

			claims.VC["@context"] = 5

			vc.JWT, err = claims.MarshalJWS(EdDSA, ed25519Signer, "did:foo:bar#key-1")
			require.NoError(t, err)

			displayVC, err := vc.CreateDisplayCredential(DisplayAllDisclosures())
			require.Error(t, err)
			require.Nil(t, displayVC)
			require.Contains(t, err.Error(), "parsing new VC from JSON")
		})
	})
}

type mockSigner struct {
	signErr error
}

func (m *mockSigner) Sign([]byte) ([]byte, error) {
	return nil, m.signErr
}

func (m *mockSigner) Headers() jose.Headers {
	return jose.Headers{"alg": "foo"}
}

func createTestSDJWTCred(
	t *testing.T, privKey ed25519.PrivateKey, opts ...MakeSDJWTOption) (sdJWTCred string, issuerID string) {
	t.Helper()

	testCred := []byte(jwtTestCredential)

	srcVC, err := parseTestCredential(t, testCred)
	require.NoError(t, err)

	sdjwt, err := srcVC.MakeSDJWT(afgojwt.NewEd25519Signer(privKey), srcVC.Issuer.ID+"#keys-1", opts...)
	require.NoError(t, err)

	return sdjwt, srcVC.Issuer.ID
}
