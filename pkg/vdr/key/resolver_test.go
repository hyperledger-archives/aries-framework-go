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

		g1g2    = "did:key:z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo"                                                                                                                                                                                                           //nolint:lll
		g1g2KID = "did:key:z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo#z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo" //nolint:lll
		g1g2B58 = "26jjNXrWtHvbrVaiYBKcFRkCvzyTUfg1W4odspRJjfQRfoT33jr91dEn2wqzaWVVVw1WmFwpGxrioYvy3sbvgphfu2D4nJUvrmQ7ZtoykgXA4EuJhmmV3TnnfHnBkKKBWn5q"                                                                                                                                                                                                                                                                                        //nolint:lll
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

	t.Run("G1G2 concatenated keys resolved as Bls12381G2Key2020", func(t *testing.T) {
		docResolution, err := v.Read(g1g2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, g1g2, g1g2KID, bls12381G2Key2020, g1g2B58)
	})
}

func TestReadP256(t *testing.T) {
	v := New()

	const (
		k1       = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z"
		k1KID    = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z#zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z" //nolint:lll
		k1Base58 = "3YRwdf868zp2t8c4oT4XdYfCihMsfR1zrVYyXS5SS4FwQ7wftDfoY5nohvhdgSk9LxyfzjTLzffJPmHgFBqizX9v"
		k2       = "did:key:zrusAFgBbf84b8mBz8Cmy8UoFWKV52EaeRnK86vnLo4Z5QoRypE6hXVPN2urevZMAMtcTaCDFLWBaE1Q3jmdb1FHgve"
		k2KID    = "did:key:zrusAFgBbf84b8mBz8Cmy8UoFWKV52EaeRnK86vnLo4Z5QoRypE6hXVPN2urevZMAMtcTaCDFLWBaE1Q3jmdb1FHgve#zrusAFgBbf84b8mBz8Cmy8UoFWKV52EaeRnK86vnLo4Z5QoRypE6hXVPN2urevZMAMtcTaCDFLWBaE1Q3jmdb1FHgve" //nolint:lll
		k2Base58 = "3m5KFNv9LgHyajqGJNEEz5JbqAPS4KHwKQu28g7vLC8xXw4MTyJusqsZMkSN2sYQbK5tvbnruySsWjBXJuQkZMva"
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k1, k1KID, jsonWebKey2020, k1Base58)
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k2, k2KID, jsonWebKey2020, k2Base58)
	})
}

func TestReadP384(t *testing.T) {
	v := New()

	const (
		k1       = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU"                                                                                                                                         //nolint:lll
		k1KID    = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU#zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU" //nolint:lll
		k1Base58 = "tAjHMcvoBXs3BSihDV85trHmstc3V3vTP7o2Si72eCWdVzeGgGvRd8h5neHEbqSL989h53yNj7M7wHckB2bKpGKQjnPDD7NphDa9nUUBggCB6aCWterfdXbH5DfWPZx5oXU"                                                                                                                                                     //nolint:lll
		k2       = "did:key:zFwepbBSaPFjt5T1zWptHaXugLNxHYABfJrDoAZRYxKjNkpdfrniF3pvYQAXwxVB7afhmsgzYtSCzTVZQ3F5SPHzP5PuHgtBGNYucZTSrnA7yTTDr7WGQZaTTkJWfiH47jW5ahU"                                                                                                                                         //nolint:lll
		k2KID    = "did:key:zFwepbBSaPFjt5T1zWptHaXugLNxHYABfJrDoAZRYxKjNkpdfrniF3pvYQAXwxVB7afhmsgzYtSCzTVZQ3F5SPHzP5PuHgtBGNYucZTSrnA7yTTDr7WGQZaTTkJWfiH47jW5ahU#zFwepbBSaPFjt5T1zWptHaXugLNxHYABfJrDoAZRYxKjNkpdfrniF3pvYQAXwxVB7afhmsgzYtSCzTVZQ3F5SPHzP5PuHgtBGNYucZTSrnA7yTTDr7WGQZaTTkJWfiH47jW5ahU" //nolint:lll
		k2Base58 = "3n4GxVYnCBm5RWHJcUyUzCRZ5SLAwdN4E513ZHfZZZABmVbBANirrYnhZRjiMQKZ4TdDiPaXxwqVzFFMQke78kmbeZHAHa7mCvU3BuRS6G1URwVFm8K64SHcwwiSy2X7LuU"                                                                                                                                                     //nolint:lll
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k1, k1KID, jsonWebKey2020, k1Base58)
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k2, k2KID, jsonWebKey2020, k2Base58)
	})
}

func TestRead521(t *testing.T) {
	v := New()

	const (
		k1       = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK"                                                                                                                                                                                          //nolint:lll
		k1KID    = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK#zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK" //nolint:lll
		k1Base58 = "mTQ9pPr2wkKdiTHhVG7xmLwyJ5mrgq1FKcHFz2XJprs4zAPtjXWFiEz6vsscbseSEzGdjAVzcUhwdodT5cbrRjQqFdz8d1yYVqMHXsVCdCUrmWNNHcZLJeYCn1dCtQX9YRVdDFfnzczKFxDXe9HusLqBWTobbxVvdj9cTi7rSWVznP5Emfo"                                                                                                                                                                                                       //nolint:lll
		k2       = "did:key:zWGhiwzmESrRykvUMCSNCadMyhzgAMVXST3KLSxY5unckUdYaGBZs59WMkMggeenMFAr938YxbEesbQ7myxmqDYo3m7xgFu8ppYDx2waz2Lw6eD9aADLn6Cw6Q6gTrH6sry211Z16nvVW25dsY6bZKhGKt4DeB1gGfvBk8bxwKuxTUtZrgwrMm1S"                                                                                                                                                                                          //nolint:lll
		k2KID    = "did:key:zWGhiwzmESrRykvUMCSNCadMyhzgAMVXST3KLSxY5unckUdYaGBZs59WMkMggeenMFAr938YxbEesbQ7myxmqDYo3m7xgFu8ppYDx2waz2Lw6eD9aADLn6Cw6Q6gTrH6sry211Z16nvVW25dsY6bZKhGKt4DeB1gGfvBk8bxwKuxTUtZrgwrMm1S#zWGhiwzmESrRykvUMCSNCadMyhzgAMVXST3KLSxY5unckUdYaGBZs59WMkMggeenMFAr938YxbEesbQ7myxmqDYo3m7xgFu8ppYDx2waz2Lw6eD9aADLn6Cw6Q6gTrH6sry211Z16nvVW25dsY6bZKhGKt4DeB1gGfvBk8bxwKuxTUtZrgwrMm1S" //nolint:lll
		k2Base58 = "h5hR4XdKFH5BL77TASdHJECqKdja3H97ZC1cEYuuHUcoAyMZwPEyLu4J8vq52YAzRp18hU2s9anCV5up9Uq8YY2VQEJhHUG8An49FeUa3RyJgjWqhjZndUoe6cxy8EKQjsTEtK8DhJys9wKobqnucpetcxJ5ZW2wgTaxyEpWjXzSLZvTTPv"                                                                                                                                                                                                       //nolint:lll
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k1, k1KID, jsonWebKey2020, k1Base58)
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertBase58Doc(t, docResolution.DIDDocument, k2, k2KID, jsonWebKey2020, k2Base58)
	})
}
