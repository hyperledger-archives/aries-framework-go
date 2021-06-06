/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/ed25519"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
)

func TestBuild(t *testing.T) {
	const (
		pubKeyBase58Ed25519 = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		pubKeyBase58BBS     = "25EEkQtcLKsEzQ6JTo9cg4W7NHpaurn4Wg6LaNPFq6JQXnrP91SDviUz7KrJVMJd76CtAZFsRLYzvgX2JGxo2ccUHtuHk7ELCWwrkBDfrXCFVfqJKDootee9iVaF6NpdJtBE" //nolint:lll
		pubKeyBase58P256    = "3YRwdf868zp2t8c4oT4XdYfCihMsfR1zrVYyXS5SS4FwQ7wftDfoY5nohvhdgSk9LxyfzjTLzffJPmHgFBqizX9v"
		pubKeyBase58P384    = "tAjHMcvoBXs3BSihDV85trHmstc3V3vTP7o2Si72eCWdVzeGgGvRd8h5neHEbqSL989h53yNj7M7wHckB2bKpGKQjnPDD7NphDa9nUUBggCB6aCWterfdXbH5DfWPZx5oXU"                                                 //nolint:lll
		pubKeyBase58P521    = "mTQ9pPr2wkKdiTHhVG7xmLwyJ5mrgq1FKcHFz2XJprs4zAPtjXWFiEz6vsscbseSEzGdjAVzcUhwdodT5cbrRjQqFdz8d1yYVqMHXsVCdCUrmWNNHcZLJeYCn1dCtQX9YRVdDFfnzczKFxDXe9HusLqBWTobbxVvdj9cTi7rSWVznP5Emfo" //nolint:lll
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

		pubKey := did.VerificationMethod{
			Type:  jsonWebKey2020,
			Value: base58.Decode(pubKeyBase58P256),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP256Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP256Doc(t, docResolution.DIDDocument)
	})

	t.Run("build with NIST P-384 key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  jsonWebKey2020,
			Value: base58.Decode(pubKeyBase58P384),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP384Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP384Doc(t, docResolution.DIDDocument)
	})

	t.Run("build with NIST P-521 key type", func(t *testing.T) {
		v := New()

		pubKey := did.VerificationMethod{
			Type:  jsonWebKey2020,
			Value: base58.Decode(pubKeyBase58P521),
		}

		docResolution, err := v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP521Doc(t, docResolution.DIDDocument)

		docResolution, err = v.Create(&did.Doc{VerificationMethod: []did.VerificationMethod{pubKey}})
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertP521Doc(t, docResolution.DIDDocument)
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
		didKey       = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z"
		didKeyID     = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z#zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z" //nolint:lll
		pubKeyBase58 = "3YRwdf868zp2t8c4oT4XdYfCihMsfR1zrVYyXS5SS4FwQ7wftDfoY5nohvhdgSk9LxyfzjTLzffJPmHgFBqizX9v"
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertP384Doc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-8
	const (
		didKey       = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU"                                                                                                                                         //nolint:lll
		didKeyID     = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU#zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU" //nolint:lll
		pubKeyBase58 = "tAjHMcvoBXs3BSihDV85trHmstc3V3vTP7o2Si72eCWdVzeGgGvRd8h5neHEbqSL989h53yNj7M7wHckB2bKpGKQjnPDD7NphDa9nUUBggCB6aCWterfdXbH5DfWPZx5oXU"                                                                                                                                                     //nolint:lll
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertP521Doc(t *testing.T, doc *did.Doc) {
	// did key from  https://w3c-ccg.github.io/did-method-key/#example-9
	const (
		didKey       = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK"                                                                                                                                                                                          //nolint:lll
		didKeyID     = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK#zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK" //nolint:lll
		pubKeyBase58 = "mTQ9pPr2wkKdiTHhVG7xmLwyJ5mrgq1FKcHFz2XJprs4zAPtjXWFiEz6vsscbseSEzGdjAVzcUhwdodT5cbrRjQqFdz8d1yYVqMHXsVCdCUrmWNNHcZLJeYCn1dCtQX9YRVdDFfnzczKFxDXe9HusLqBWTobbxVvdj9cTi7rSWVznP5Emfo"                                                                                                                                                                                                       //nolint:lll
	)

	assertDualBase58Doc(t, doc, didKey, didKeyID, jsonWebKey2020, pubKeyBase58,
		"", "", "")
}

func assertBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58 string) {
	assertDualBase58Doc(t, doc, didKey, didKeyID, didKeyType, pubKeyBase58, didKeyID, didKeyType, pubKeyBase58)
}

func assertDualBase58Doc(t *testing.T, doc *did.Doc, didKey, didKeyID, didKeyType, pubKeyBase58,
	agreementKeyID, keyAgreementType, keyAgreementBase58 string) {
	// validate @context
	require.Equal(t, schemaDIDV1, doc.Context[0])

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
