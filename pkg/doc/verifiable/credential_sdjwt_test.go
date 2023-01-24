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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/jwt"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/common"
	"github.com/hyperledger/aries-framework-go/pkg/doc/sdjwt/issuer"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

func TestParseSDJWT(t *testing.T) {
	testCred := []byte(jwtTestCredential)

	credObj := map[string]interface{}{}

	err := json.Unmarshal(testCred, &credObj)
	require.NoError(t, err)

	credSubj := map[string]interface{}{
		"name": "Foo Bar",
		"address": map[string]interface{}{
			"street-number": 123,
			"street":        "Anywhere Lane",
			"city":          "R'lyeh",
		},
	}

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	sdjwtCred, err := issuer.New(
		"foo:bar:baz",
		credSubj,
		nil,
		jwt.NewEd25519Signer(privKey),
		issuer.WithStructuredClaims(true),
	)
	require.NoError(t, err)

	sdAlg, ok := sdjwtCred.SignedJWT.Payload["_sd_alg"].(string)
	require.True(t, ok)

	delete(sdjwtCred.SignedJWT.Payload, "_sd_alg")

	credObj["credentialSubject"] = sdjwtCred.SignedJWT.Payload

	credBytes, err := json.Marshal(credObj)
	require.NoError(t, err)

	ed25519Signer, err := newCryptoSigner(kms.ED25519Type)
	require.NoError(t, err)

	vc, err := parseTestCredential(t, credBytes)
	require.NoError(t, err)

	vc.SDJWTHashAlg = sdAlg

	jwtClaims, err := vc.JWTClaims(false)
	require.NoError(t, err)

	vcJWT, err := jwtClaims.MarshalJWS(EdDSA, ed25519Signer, vc.Issuer.ID+"#keys-"+keyID)
	require.NoError(t, err)

	cffi := common.CombinedFormatForIssuance{
		SDJWT:       vcJWT,
		Disclosures: sdjwtCred.Disclosures,
	}

	sdJWTString := cffi.Serialize()

	t.Run("success", func(t *testing.T) {
		newVC, e := ParseCredential([]byte(sdJWTString),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), vc.Issuer.ID)))
		require.NoError(t, e)

		fmt.Printf("VC: %#v\n", newVC)
	})

	t.Run("success with mock holder binding", func(t *testing.T) {
		mockHolderBinding := "<mock holder binding>"

		newVC, e := ParseCredential([]byte(sdJWTString+common.CombinedFormatSeparator+mockHolderBinding),
			WithPublicKeyFetcher(createDIDKeyFetcher(t, ed25519Signer.PublicKeyBytes(), vc.Issuer.ID)),
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
