/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
)

func TestCreateDIDKey(t *testing.T) {
	const (
		edPubKeyBase58     = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		edExpectedDIDKey   = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		edExpectedDIDKeyID = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll

		bbsPubKeyBase58     = "25EEkQtcLKsEzQ6JTo9cg4W7NHpaurn4Wg6LaNPFq6JQXnrP91SDviUz7KrJVMJd76CtAZFsRLYzvgX2JGxo2ccUHtuHk7ELCWwrkBDfrXCFVfqJKDootee9iVaF6NpdJtBE"                                                                                                                                                    //nolint:lll
		bbsExpectedDIDKey   = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY"                                                                                                                                         //nolint:lll
		bbsExpectedDIDKeyID = "did:key:zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY#zUC7K4ndUaGZgV7Cp2yJy6JtMoUHY6u7tkcSYUvPrEidqBmLCTLmi6d5WvwnUqejscAkERJ3bfjEiSYtdPkRSE8kSa11hFBr4sTgnbZ95SJj19PN2jdvJjyzpSZgxkyyxNnBNnY" //nolint:lll

		ecP256PubKeyBase58     = "3YRwdf868zp2t8c4oT4XdYfCihMsfR1zrVYyXS5SS4FwQ7wftDfoY5nohvhdgSk9LxyfzjTLzffJPmHgFBqizX9v"
		ecP256ExpectedDIDKey   = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z"                                                                                             //nolint:lll
		ecP256ExpectedDIDKeyID = "did:key:zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z#zrurwcJZss4ruepVNu1H3xmSirvNbzgBk9qrCktB6kaewXnJAhYWwtP3bxACqBpzjZdN7TyHNzzGGSSH5qvZsSDir9z" //nolint:lll

		ecP384PubKeyBase58     = "tAjHMcvoBXs3BSihDV85trHmstc3V3vTP7o2Si72eCWdVzeGgGvRd8h5neHEbqSL989h53yNj7M7wHckB2bKpGKQjnPDD7NphDa9nUUBggCB6aCWterfdXbH5DfWPZx5oXU"                                                                                                                                                     //nolint:lll
		ecP384ExpectedDIDKey   = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU"                                                                                                                                         //nolint:lll
		ecP384ExpectedDIDKeyID = "did:key:zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU#zFwfeyrSyWdksRYykTGGtagWazFB5zS4CjQcxDMQSNmCTQB5QMqokx2VJz4vBB2hN1nUrYDTuYq3kd1BM5cUCfFD4awiNuzEBuoy6rZZTMCsZsdvWkDXY6832qcAnzE7YGw43KU" //nolint:lll

		ecP521PubKeyBase58     = "mTQ9pPr2wkKdiTHhVG7xmLwyJ5mrgq1FKcHFz2XJprs4zAPtjXWFiEz6vsscbseSEzGdjAVzcUhwdodT5cbrRjQqFdz8d1yYVqMHXsVCdCUrmWNNHcZLJeYCn1dCtQX9YRVdDFfnzczKFxDXe9HusLqBWTobbxVvdj9cTi7rSWVznP5Emfo"                                                                                                                                                                                                       //nolint:lll
		ecP521ExpectedDIDKey   = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK"                                                                                                                                                                                          //nolint:lll
		ecP521ExpectedDIDKeyID = "did:key:zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK#zWGhj2NTyCiehTPioanYSuSrfB7RJKwZj6bBUDNojfGEA21nr5NcBsHme7hcVSbptpWKarJpTcw814J3X8gVU9gZmeKM27JpGA5wNMzt8JZwjDyf8EzCJg5ve5GR2Xfm7d9Djp73V7s35KPeKe7VHMzmL8aPw4XBniNej5sXapPFoBs5R8m195HK" //nolint:lll

		bbsPubKeyG1Base58       = "6TBZrWMsPSFrJ2u7xFNyNA6VZs3gWpCwLi4jk8gB9EQ1bgNYK2Zjsxhku68mypBHke"
		bbsPubKeyG2Base58       = "26jjNXrWtHvbrVaiYBKcFRkCvzyTUfg1W4odspRJjfQRfoT33jr91dEn2wqzaWVVVw1WmFwpGxrioYvy3sbvgphfu2D4nJUvrmQ7ZtoykgXA4EuJhmmV3TnnfHnBkKKBWn5q"                                                                                                                                                                                                                                                                                        //nolint:lll
		bbsExpectedG1G2DIDKey   = "did:key:z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo"                                                                                                                                                                                                           //nolint:lll
		bbsExpectedG1G2DIDKeyID = "did:key:z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo#z5TcDLDFhBEndYdwFKkQMgVTgtRHx2sniQisVxdiXZ96pcrRy2ehWvcHfhSrfDmozq8dQNxhu2u7y9FUKJ8R3VPZNPjEgsozTSx47WysNM9GESUMmyniFxbdbpxNdocx6SbRyf6nBTFzoXojbWjSsDN4LhNz1sAMzTXgh5HvLYtYzJXo1JtLZBwHgmvtWyEQqtxtjV2eo" //nolint:lll
	)

	tests := []struct {
		name     string
		keyB58   string
		DIDKey   string
		DIDKeyID string
		keyCode  uint64
	}{
		{
			name:     "test ED25519",
			keyB58:   edPubKeyBase58,
			DIDKey:   edExpectedDIDKey,
			DIDKeyID: edExpectedDIDKeyID,
			keyCode:  ED25519PubKeyMultiCodec,
		},
		{
			name:     "test BBS+",
			keyB58:   bbsPubKeyBase58,
			DIDKey:   bbsExpectedDIDKey,
			DIDKeyID: bbsExpectedDIDKeyID,
			keyCode:  BLS12381g2PubKeyMultiCodec,
		},
		{
			name:     "test P-256",
			keyB58:   ecP256PubKeyBase58,
			DIDKey:   ecP256ExpectedDIDKey,
			DIDKeyID: ecP256ExpectedDIDKeyID,
			keyCode:  P256PubKeyMultiCodec,
		},
		{
			name:     "test P-384",
			keyB58:   ecP384PubKeyBase58,
			DIDKey:   ecP384ExpectedDIDKey,
			DIDKeyID: ecP384ExpectedDIDKeyID,
			keyCode:  P384PubKeyMultiCodec,
		},
		{
			name:     "test P-521",
			keyB58:   ecP521PubKeyBase58,
			DIDKey:   ecP521ExpectedDIDKey,
			DIDKeyID: ecP521ExpectedDIDKeyID,
			keyCode:  P521PubKeyMultiCodec,
		},
		{
			name:     "test BBS+ with G1G2",
			keyB58:   bbsPubKeyG2Base58,
			DIDKey:   bbsExpectedG1G2DIDKey,
			DIDKeyID: bbsExpectedG1G2DIDKeyID,
			keyCode:  BLS12381g1g2PubKeyMultiCodec,
		},
	}

	for _, test := range tests {
		tc := test
		t.Run(tc.name+" CreateDIDKey", func(t *testing.T) {
			keyBytes := base58.Decode(tc.keyB58)
			// append G1G2 public keys for Creation of DIDKey for BLS12381g1g2PubKeyMultiCodec
			if tc.keyCode == BLS12381g1g2PubKeyMultiCodec {
				g1Bytes := base58.Decode(bbsPubKeyG1Base58)
				keyBytes = append(g1Bytes, keyBytes...)
			}

			didKey, keyID := CreateDIDKeyByCode(tc.keyCode, keyBytes)

			require.Equal(t, tc.DIDKey, didKey)
			require.Equal(t, tc.DIDKeyID, keyID)
		})

		t.Run(tc.name+" PubKeyFromFingerprint success", func(t *testing.T) {
			pubKey, code, err := PubKeyFromFingerprint(strings.Split(tc.DIDKeyID, "#")[1])
			require.Equal(t, tc.keyCode, code)
			require.NoError(t, err)

			require.Equal(t, base58.Encode(pubKey), tc.keyB58)
		})

		t.Run(tc.name+" PubKeyFromDIDKey", func(t *testing.T) {
			pubKey, err := PubKeyFromDIDKey(tc.DIDKey)
			require.Equal(t, tc.keyB58, base58.Encode(pubKey))
			require.NoError(t, err)
		})
	}

	t.Run("test PubKeyFromFingerprint fail", func(t *testing.T) {
		badDIDKeyID := "AB" + strings.Split(edExpectedDIDKeyID, "#")[1][2:]

		_, _, err := PubKeyFromFingerprint(badDIDKeyID)
		require.EqualError(t, err, "unknown key encoding")
	})

	t.Run("invalid fingerprint", func(t *testing.T) {
		_, _, err := PubKeyFromFingerprint("")
		require.Error(t, err)

		_, _, err = PubKeyFromFingerprint("a6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
		require.Error(t, err)
	})
}

func TestDIDKeyEd25519(t *testing.T) {
	const (
		k1       = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH"
		k1Base58 = "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u"
		k1KeyID  = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH" //nolint:lll
	)

	didKey, keyID := CreateDIDKey(base58.Decode(k1Base58))

	require.Equal(t, didKey, k1)
	require.Equal(t, keyID, k1KeyID)

	pubKey, err := PubKeyFromDIDKey(k1)
	require.Equal(t, k1Base58, base58.Encode(pubKey))
	require.NoError(t, err)
}
