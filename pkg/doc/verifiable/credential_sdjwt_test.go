/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package verifiable

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"

	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/holder"

	afgojwt "github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/signature"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestParseSDJWT(t *testing.T) {
	ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	sdJWTString, issuerID := createTestSDJWTCred(t, ed25519Signer)

	t.Run("success", func(t *testing.T) {
		newVC, e := ParseCredential([]byte(sdJWTString),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), issuerID)))
		require.NoError(t, e)

		fmt.Printf("VC: %#v\n", newVC)
	})

	t.Run("success with mock holder binding", func(t *testing.T) {
		mockHolderBinding := "<mock holder binding>"

		newVC, e := ParseCredential([]byte(sdJWTString+common.CombinedFormatSeparator+mockHolderBinding),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), issuerID)),
			WithSDJWTPresentation())
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
	ed25519Signer, e := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, e)

	sourceCred, _ := createTestSDJWTCred(t, ed25519Signer)

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

			// fmt.Printf("source cred: %s\n", sourceCred)
			// fmt.Printf("result cred: %s\n", resultCred)

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
			require.NotEmpty(t, res.HolderBinding)
		})

		t.Run("disclose required and some if-available claims", func(t *testing.T) {
			resultCred, err := newVC.MarshalWithDisclosure(
				DiscloseGivenRequired([]string{"name"}),
				DiscloseGivenIfAvailable([]string{"name", "city", "favourite-animal"}))
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
				DiscloseGivenRequired([]string{"id", "university"}),
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
			require.Len(t, res.Disclosures, 2)
			require.NotEmpty(t, res.HolderBinding)
		})
	})

	t.Run("failure", func(t *testing.T) {
		newVC, e2 := ParseCredential([]byte(sourceCred), WithDisabledProofCheck())
		require.NoError(t, e2)

		t.Run("incompatible options", func(t *testing.T) {
			resultCred, err := newVC.MarshalWithDisclosure(
				DiscloseAll(),
				DiscloseGivenIfAvailable([]string{"city", "favourite-animal"}))
			require.Error(t, err)
			require.Empty(t, resultCred)
			require.Contains(t, err.Error(), "incompatible options provided")

			resultCred, err = newVC.MarshalWithDisclosure(
				DiscloseGivenRequired([]string{"name"}),
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

				resultCred, err := badVC.MarshalWithDisclosure(DiscloseGivenRequired([]string{"name"}))
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
		sdjwt, err := vc.MakeSDJWT(afgojwt.NewEd25519Signer(privKey), "did:example:abc123#key-1")
		require.NoError(t, err)

		fmt.Println(sdjwt)

		_, err = ParseCredential([]byte(sdjwt), WithPublicKeyFetcher(holderPublicKeyFetcher(pubKey)))
		require.NoError(t, err)
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

type mockSigner struct {
	signErr error
}

func (m *mockSigner) Sign([]byte) ([]byte, error) {
	return nil, m.signErr
}

func (m *mockSigner) Headers() jose.Headers {
	return jose.Headers{"alg": "foo"}
}

func createTestSDJWTCred(t *testing.T, edDSASigner signature.Signer) (sdJWTCred string, issuerID string) {
	t.Helper()

	testCred := []byte(jwtTestCredential)

	credObj := map[string]interface{}{}

	err := json.Unmarshal(testCred, &credObj)
	require.NoError(t, err)

	credSubj := map[string]interface{}{
		"name": "Foo Bar",
		"address": map[string]interface{}{
			"street-number": 123,
			"street":        "Anywhere Lane",
			"city":          "England",
		},
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sdjwtCred, err := issuer.New(
		"foo:bar:baz",
		credSubj,
		nil,
		afgojwt.NewEd25519Signer(privKey),
		issuer.WithStructuredClaims(true),
	)
	require.NoError(t, err)

	sdAlg, ok := sdjwtCred.SignedJWT.Payload["_sd_alg"].(string)
	require.True(t, ok)

	delete(sdjwtCred.SignedJWT.Payload, "_sd_alg")

	credObj["credentialSubject"] = sdjwtCred.SignedJWT.Payload

	credBytes, err := json.Marshal(credObj)
	require.NoError(t, err)

	vc, err := parseTestCredential(t, credBytes)
	require.NoError(t, err)

	vc.SDJWTHashAlg = sdAlg

	jwtClaims, err := vc.JWTClaims(false)
	require.NoError(t, err)

	vcJWT, err := jwtClaims.MarshalJWS(EdDSA, edDSASigner, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	cffi := common.CombinedFormatForIssuance{
		SDJWT:       vcJWT,
		Disclosures: sdjwtCred.Disclosures,
	}

	return cffi.Serialize(), vc.Issuer.ID
}
