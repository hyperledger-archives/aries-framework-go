/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
	"github.com/hyperledger/aries-framework-go/component/models/did"
)

func TestBuild(t *testing.T) {
	const (
		pubKeyBase58Ed25519 = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		pubKeyBase58BBS     = "25EEkQtcLKsEzQ6JTo9cg4W7NHpaurn4Wg6LaNPFq6JQXnrP91SDviUz7KrJVMJd76CtAZFsRLYzvgX2JGxo2ccUHtuHk7ELCWwrkBDfrXCFVfqJKDootee9iVaF6NpdJtBE" //nolint:lll
		pubKeyBase58P256    = "Q1sFNywhsHf5Wds93YN1b97jrFiUQchN3nDgboS64kqzbTrPNN6ESCibhyNEidDMHa6M1V43dVeiFpBaUa4RXxMa"
		pubKeyBase58P384    = "7xunFyusHxhJS3tbNWcX7xHCLRPnsScaBJJQUWw8KPpTTPfUSw9RbdyQYCBaLopw6eVQJv1G4ZD4EWgnE3zmkuiGHTq5y1KAwPAUv9Q4XXBricnzAxKamSHJiX29uQqGtbux"                                                  //nolint:lll
		pubKeyBase58P521    = "CqTBHvN1FwpkcrhNddXM3zSZRF7rUNSCCBuPWRxBmNAGBMa91by5XebadFwGJ2d1AVJMbUUKmUiBGXaCDDVEDn5fthbSBosoFG4anpQextGkuHHJohZxeLrGuyHc4JZYGyWFbAXVRKTMFRxuF8eQ88zqvjEV6k8oNbQ6vELYFp9CjQudG7cqP" //nolint:lll
	)

	t.Run("validate did:key compliance with generic syntax", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  ed25519VerificationKey2018,
			Value: ed25519.PublicKey(base58.Decode(pubKeyBase58Ed25519)),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		d, err := did.Parse(docResolution.DIDDocument.ID)
		require.NoError(t, err)
		require.NotNil(t, d)
	})

	t.Run("build with default key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  ed25519VerificationKey2018,
			Value: base58.Decode(pubKeyBase58Ed25519),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertEd25519Doc(t, docResolution.DIDDocument)
	})

	t.Run("build with BLS12381G2 key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  bls12381G2Key2020,
			Value: base58.Decode(pubKeyBase58BBS),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBBSDoc(t, docResolution.DIDDocument)
	})

	t.Run("build with NIST P-256 key type", func(t *testing.T) {
		v := New()

		x, y := elliptic.Unmarshal(elliptic.P256(), base58.Decode(pubKeyBase58P256))
		require.NotNil(t, x, "error parsing pubKeyBase58P256 public key")
		key := ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     x,
			Y:     y,
		}
		j, err := jwksupport.JWKFromKey(&key)
		require.NoError(t, err, "error creating JWK from public key: %v", err)

		vm, err := did.NewVerificationMethodFromJWK("id", jsonWebKey2020, "", j)
		require.NoError(t, err, "error creating verification method from JWK")

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP256Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP256Doc(t, docResolution.DIDDocument)
	})

	t.Run("build with NIST P-384 key type", func(t *testing.T) {
		v := New()

		x, y := elliptic.Unmarshal(elliptic.P384(), base58.Decode(pubKeyBase58P384))
		require.NotNil(t, x, "error parsing pubKeyBase58P384 public key")
		key := ecdsa.PublicKey{
			Curve: elliptic.P384(),
			X:     x,
			Y:     y,
		}
		j, err := jwksupport.JWKFromKey(&key)
		require.NoError(t, err, "error creating JWK from public key: %v", err)

		vm, err := did.NewVerificationMethodFromJWK("id", jsonWebKey2020, "", j)
		require.NoError(t, err, "error creating verification method from JWK")

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP384Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP384Doc(t, docResolution.DIDDocument)
	})

	t.Run("build with NIST P-521 key type", func(t *testing.T) {
		v := New()

		x, y := elliptic.Unmarshal(elliptic.P521(), base58.Decode(pubKeyBase58P521))
		require.NotNil(t, x, "error parsing pubKeyBase58P521 public key")
		key := ecdsa.PublicKey{
			Curve: elliptic.P521(),
			X:     x,
			Y:     y,
		}
		j, err := jwksupport.JWKFromKey(&key)
		require.NoError(t, err, "error creating JWK from public key: %v", err)

		vm, err := did.NewVerificationMethodFromJWK("id", jsonWebKey2020, "", j)
		require.NoError(t, err, "error creating verification method from JWK")

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP521Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{*vm}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP521Doc(t, docResolution.DIDDocument)
	})

	t.Run("test create JsonWebKey2020 with no jwk", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  jsonWebKey2020,
			Value: base58.Decode(pubKeyBase58P256),
		}

		_, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.Error(t, err, "expecting an error")
		require.Contains(t, err.Error(), "jsonWebKey is required", "incorrect error message")
	})

	t.Run("test create with invalid key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  "invalid",
			Value: base58.Decode(pubKeyBase58P256),
		}

		_, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.Error(t, err, "expecting an error")
		require.Contains(t, err.Error(), "not supported public key type", "incorrect error message")
	})
}

func assertEd25519Doc(t *testing.T, doc *did.Doc) {
	const (
		didKey         = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		didKeyID       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
		agreementKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc" //nolint:lll

		pubKeyBase58       = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		keyAgreementBase58 = "JhNWeSVLMYccCk7iopQW4guaSJTojqpMEELgSLhKwRr"
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, ed25519VerificationKey2018, pubKeyBase58,
		agreementKeyID, x25519KeyAgreementKey2019, keyAgreementBase58)
}

func assertBBSDoc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-6
	const (
		didKey       = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY"                                                                                                                                         //nolint:lll
		didKeyID     = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY#zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY" //nolint:lll
		pubKeyBase58 = "25EEkQtcLKsEzQ6JTo9cg4W7NHpaurn4Wg6LaNPFq6JQXnrP91SDviUz7KrJVMJd76CtAZFsRLYzvgX2JGxo2ccUHtuHk7ELCWwrkBDfrXCFVfqJKDootee9iVaF6NpdJtBE"                                                                                                                                                    //nolint:lll
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, bls12381G2Key2020, pubKeyBase58,
		"", "", "")
}

func assertP256Doc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-7
	const (
		didKey       = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
		didKeyID     = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169" //nolint:lll
		pubKeyBase58 = "Q1sFNywhsHf5Wds93YN1b97jrFiUQchN3nDgboS64kqzbTrPNN6ESCibhyNEidDMHa6M1V43dVeiFpBaUa4RXxMa"
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertP384Doc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-8
	const (
		didKey       = "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"                                                                         //nolint:lll
		didKeyID     = "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9#z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9" //nolint:lll
		pubKeyBase58 = "7xunFyusHxhJS3tbNWcX7xHCLRPnsScaBJJQUWw8KPpTTPfUSw9RbdyQYCBaLopw6eVQJv1G4ZD4EWgnE3zmkuiGHTq5y1KAwPAUv9Q4XXBricnzAxKamSHJiX29uQqGtbux"                    //nolint:lll
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertP521Doc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-9
	const (
		didKey       = "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7"                                                                                                  //nolint:lll
		didKeyID     = "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7#z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7" //nolint:lll
		pubKeyBase58 = "CqTBHvN1FwpkcrhNddXM3zSZRF7rUNSCCBuPWRxBmNAGBMa91by5XebadFwGJ2d1AVJMbUUKmUiBGXaCDDVEDn5fthbSBosoFG4anpQextGkuHHJohZxeLrGuyHc4JZYGyWFbAXVRKTMFRxuF8eQ88zqvjEV6k8oNbQ6vELYFp9CjQudG7cqP"                     //nolint:lll
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58 string) {
	assertDualBase58Doc(t, doc, didKey, didKeyID, didKeyType, pubKeyBase58, didKeyID, didKeyType, pubKeyBase58)
}

func assertDualBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58,
	agreementKeyID, keyAgreementType, keyAgreementBase58 string) {
	var context string
	switch ctx := doc.Context.(type) {
	case string:
		context = ctx
	case []string:
		context = ctx[0]
	case []interface{}:
		var ok bool
		context, ok = ctx[0].(string)
		require.True(t, ok)
	}

	// validate @context
	require.Equal(t, schemaDIDV1, context)

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := &did.VerificationMethod{
		ID:         didKeyID,
		Type:       didKeyType,
		Controller: didKey,
		Value:      base58.Decode(pubKeyBase58),
	}

	expectedKeyAgreement := &did.VerificationMethod{
		ID:         agreementKeyID,
		Type:       keyAgreementType,
		Controller: didKey,
		Value:      base58.Decode(keyAgreementBase58),
	}

	// validate publicKey
	assertPubKey(t, expectedPubKey, &doc.VerificationMethod[0])

	// validate assertionMethod
	assertPubKey(t, expectedPubKey, &doc.AssertionMethod[0].VerificationMethod)

	// validate authentication
	assertPubKey(t, expectedPubKey, &doc.Authentication[0].VerificationMethod)

	// validate capabilityDelegation
	assertPubKey(t, expectedPubKey, &doc.CapabilityDelegation[0].VerificationMethod)

	// validate capabilityInvocation
	assertPubKey(t, expectedPubKey, &doc.CapabilityInvocation[0].VerificationMethod)

	if len(doc.KeyAgreement) > 0 {
		// validate keyAgreement
		assertPubKey(t, expectedKeyAgreement, &doc.KeyAgreement[0].VerificationMethod)
	}
}

func assertPubKey(t *testing.T, expectedPubKey, actualPubKey *did.VerificationMethod) {
	require.NotNil(t, actualPubKey)
	require.Equal(t, expectedPubKey.ID, actualPubKey.ID)
	require.Equal(t, expectedPubKey.Type, actualPubKey.Type)
	require.Equal(t, expectedPubKey.Controller, actualPubKey.Controller)
	require.Equal(t, expectedPubKey.Value, actualPubKey.Value)
}

func assertJSONWebKeyDoc(t *testing.T, doc *did.Doc, didKey, didKeyID string,
	pubKeyCurve elliptic.Curve, pubKeyX, pubKeyY *big.Int) {
	assertDualJSONWebKeyDoc(t, doc, didKey, didKeyID, pubKeyCurve, pubKeyX, pubKeyY,
		didKeyID, pubKeyCurve, pubKeyX, pubKeyY)
}

func createVerificationMethodFromXAndY(t *testing.T, didKeyID, didKey string,
	curve elliptic.Curve, x, y *big.Int) *did.VerificationMethod {
	publicKey := ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	j, err := jwksupport.JWKFromKey(&publicKey)
	require.Nil(t, err, "error creating expected JWK from public key %w", err)

	verificationMethod, err := did.NewVerificationMethodFromJWK(didKeyID, jsonWebKey2020, didKey, j)
	require.Nil(t, err, "error creating expected JWK %w", err)

	return verificationMethod
}

func assertDualJSONWebKeyDoc(t *testing.T, doc *did.Doc, didKey, didKeyID string,
	pubKeyCurve elliptic.Curve, pubKeyX, pubKeyY *big.Int,
	agreementKeyID string, keyAgreementCurve elliptic.Curve, keyAgreementX, keyAgreementY *big.Int) {
	var context string
	switch ctx := doc.Context.(type) {
	case string:
		context = ctx
	case []string:
		context = ctx[0]
	case []interface{}:
		var ok bool
		context, ok = ctx[0].(string)
		require.True(t, ok)
	}

	// validate @context
	require.Equal(t, schemaDIDV1, context)

	// validate id
	require.Equal(t, didKey, doc.ID)

	expectedPubKey := createVerificationMethodFromXAndY(t, didKeyID, didKey, pubKeyCurve, pubKeyX, pubKeyY)
	expectedKeyAgreement := createVerificationMethodFromXAndY(t, agreementKeyID, didKey,
		keyAgreementCurve, keyAgreementX, keyAgreementY)

	// validate publicKey
	assertPubJSONWebKey(t, expectedPubKey, &doc.VerificationMethod[0])

	// validate assertionMethod
	assertPubJSONWebKey(t, expectedPubKey, &doc.AssertionMethod[0].VerificationMethod)

	// validate authentication
	assertPubJSONWebKey(t, expectedPubKey, &doc.Authentication[0].VerificationMethod)

	// validate capabilityDelegation
	assertPubJSONWebKey(t, expectedPubKey, &doc.CapabilityDelegation[0].VerificationMethod)

	// validate capabilityInvocation
	assertPubJSONWebKey(t, expectedPubKey, &doc.CapabilityInvocation[0].VerificationMethod)

	if len(doc.KeyAgreement) > 0 {
		// validate keyAgreement
		assertPubJSONWebKey(t, expectedKeyAgreement, &doc.KeyAgreement[0].VerificationMethod)
	}
}

func assertPubJSONWebKey(t *testing.T, expectedPubKey, actualPubKey *did.VerificationMethod) {
	require.NotNil(t, actualPubKey)
	require.Equal(t, expectedPubKey.ID, actualPubKey.ID)
	require.Equal(t, expectedPubKey.Type, actualPubKey.Type)
	require.Equal(t, expectedPubKey.Controller, actualPubKey.Controller)

	require.NotNil(t, expectedPubKey.JSONWebKey(), "expected JWK required")
	require.NotNil(t, actualPubKey.JSONWebKey(), "actual JWK required")
	require.Equal(t, "EC", actualPubKey.JSONWebKey().Kty, "only EC keys supported")
	require.Equal(t, expectedPubKey.JSONWebKey().Kty, actualPubKey.JSONWebKey().Kty)
	require.Equal(t, expectedPubKey.JSONWebKey().Crv, actualPubKey.JSONWebKey().Crv)

	expectedEcdsa, ok := expectedPubKey.JSONWebKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok, "unexpected key type")
	actualEcdsa, ok := actualPubKey.JSONWebKey().Key.(*ecdsa.PublicKey)
	require.True(t, ok, "unexpected key type")

	require.Equal(t, expectedEcdsa.X, actualEcdsa.X, "incorrect X")
	require.Equal(t, expectedEcdsa.Y, actualEcdsa.Y, "incorrect Y")
}
