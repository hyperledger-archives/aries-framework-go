/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReadInvalid(t *testing.T) {
	t.Run("validate did:key method specific ID", func(t *testing.T) {
		v := New()

		doc, err := v.Read("did:key:invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did:key method ID: invalid")
		require.Nil(t, doc)
	})

	t.Run("validate not supported public key", func(t *testing.T) {
		v := New()

		doc, err := v.Read("did:key:z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc")
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key multicodec code [0xec]") // Curve25519 public key
		require.Nil(t, doc)
	})

	t.Run("validate did:key", func(t *testing.T) {
		v := New()

		doc, err := v.Read("invalid")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did: invalid")
		require.Nil(t, doc)
	})
}

func TestReadEd25519(t *testing.T) {
	const (
		didEd25519 = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
	)

	t.Run("resolve assuming default key type", func(t *testing.T) {
		v := New()

		docResolution, err := v.Read(didEd25519)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)
		require.True(t, docResolution.DIDDocument.KeyAgreement[0].Embedded)

		assertEd25519Doc(t, docResolution.DIDDocument)
	})
}

func TestReadBBS(t *testing.T) {
	v := New()

	const (
		k1       = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY"                                                                                                                                         //nolint:lll
		k1KID    = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY#zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY" //nolint:lll
		k1Base58 = "25EEkQtcLKsEzQ6JTo9cg4W7NHpaurn4Wg6LaNPFq6JQXnrP91SDviUz7KrJVMJd76CtAZFsRLYzvgX2JGxo2ccUHtuHk7ELCWwrkBDfrXCFVfqJKDootee9iVaF6NpdJtBE"                                                                                                                                                    //nolint:lll
		k2       = "did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW"                                                                                                                                         //nolint:lll
		k2KID    = "did:key:zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW#zUC7KKoJk5ttwuuc8pmQDiUmtckEPTwcaFVZe4DSFV7fURuoRnD17D3xkBK3A9tZqdADkTTMKSwNkhjo9Hs6HfgNUXo48TNRaxU6XPLSPdRgMc15jCD5DfN34ixjoVemY62JxnW" //nolint:lll
		k2Base58 = "25VFRgQEfbJ3Pit6Z3mnZbKPK9BdQYGwdmfdcmderjYZ12BFNQYeowjMN1AYKKKcacF3UH35ZNpBqCR8y8QLeeaGLL7UKdKLcFje3VQnosesDNHsU8jBvtvYmLJusxXsSUBC"                                                                                                                                                    //nolint:lll
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k1, k1KID, bls12381G2Key2020, k1Base58)
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k2, k2KID, bls12381G2Key2020, k2Base58)
	})
}
