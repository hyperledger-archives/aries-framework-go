/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package fingerprint

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/go-jose/go-jose/v3"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/jose/jwk/jwksupport"
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
		crv      elliptic.Curve
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
			crv:      elliptic.P256(),
		},
		{
			name:     "test P-384",
			keyB58:   ecP384PubKeyBase58,
			DIDKey:   ecP384ExpectedDIDKey,
			DIDKeyID: ecP384ExpectedDIDKeyID,
			keyCode:  P384PubKeyMultiCodec,
			crv:      elliptic.P384(),
		},
		{
			name:     "test P-521",
			keyB58:   ecP521PubKeyBase58,
			DIDKey:   ecP521ExpectedDIDKey,
			DIDKeyID: ecP521ExpectedDIDKeyID,
			keyCode:  P521PubKeyMultiCodec,
			crv:      elliptic.P521(),
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
			if tc.crv != nil {
				mKeyCompressed := append([]byte{4}, pubKey...)
				x, y := elliptic.Unmarshal(tc.crv, mKeyCompressed)
				mKey := elliptic.Marshal(tc.crv, x, y)
				require.EqualValues(t, mKeyCompressed, mKey)
			}

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

func readBigInt(t *testing.T, b64 string) *big.Int {
	buf, err := base64.RawURLEncoding.DecodeString(b64)
	require.Nil(t, err, "can't parse string as b64: %v\n%s", err, b64)

	var x big.Int
	x = *x.SetBytes(buf)

	return &x
}

func TestCreateDIDKeyByJwk(t *testing.T) {
	tests := []struct {
		name     string
		kty      string
		curve    elliptic.Curve
		valB58   string
		x        string
		y        string
		DIDKey   string
		DIDKeyID string
	}{
		{
			name:     "test Ed25519",
			kty:      "OKP",
			valB58:   "B12NYF8RrR3h41TDCTJojY59usg3mbtbjnFs7Eud1Y6u",
			DIDKey:   "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
			DIDKeyID: "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", //nolint:lll
		},
		{
			name:     "test X25519",
			kty:      "OKP",
			valB58:   "4Dy8E9UaZscuPUf2GLxV44RCNL7oxmEXXkgWXaug1WKV",
			DIDKey:   "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F",
			DIDKeyID: "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F#z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F", //nolint:lll
		},
		{
			name:     "test P-256",
			kty:      "EC",
			curve:    elliptic.P256(),
			x:        "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns",
			y:        "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM",
			DIDKey:   "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
			DIDKeyID: "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv", //nolint:lll
		},
		{
			name:     "test P-384",
			kty:      "EC",
			curve:    elliptic.P384(),
			x:        "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc",
			y:        "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv",
			DIDKey:   "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9",
			DIDKeyID: "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9#z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9", //nolint:lll
		},
		{
			name:     "test P-521",
			kty:      "EC",
			curve:    elliptic.P521(),
			x:        "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
			y:        "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC",
			DIDKey:   "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7",
			DIDKeyID: "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7#z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7", //nolint:lll
		},
		{
			name:     "test EC with invalid curve",
			kty:      "EC",
			curve:    &elliptic.CurveParams{},
			x:        "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS",
			y:        "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC",
			DIDKey:   "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7",
			DIDKeyID: "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7#z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7", //nolint:lll
		},
	}

	for _, test := range tests {
		tc := test

		var (
			jwkKey *jwk.JWK
			err    error
		)

		t.Run(tc.name+" CreateDIDKeyByJwk", func(t *testing.T) {
			switch tc.name {
			case "test Ed25519":
				edKey := ed25519.PublicKey(base58.Decode(tc.valB58))
				jwkKey, err = jwksupport.JWKFromKey(edKey)
				require.NoError(t, err)
			case "test X25519":
				jwkKey, err = jwksupport.JWKFromX25519Key(base58.Decode(tc.valB58))
				require.NoError(t, err)
			default:
				x := readBigInt(t, tc.x)
				y := readBigInt(t, tc.y)
				publicKey := ecdsa.PublicKey{
					Curve: tc.curve,
					X:     x,
					Y:     y,
				}

				jwkKey, err = jwksupport.JWKFromKey(&publicKey)

				if tc.name == "test EC with invalid curve" {
					require.EqualError(t, err, "create JWK: go-jose/go-jose: unsupported/unknown elliptic curve")
					jwkKey = &jwk.JWK{
						JSONWebKey: jose.JSONWebKey{},
						Kty:        "EC",
						Crv:        "invalid",
					}
				} else {
					require.NoError(t, err)
				}
			}

			didKey, keyID, err := CreateDIDKeyByJwk(jwkKey)

			if tc.name == "test EC with invalid curve" {
				require.EqualError(t, err, "unsupported crv invalid")
				return
			}

			require.NoError(t, err)
			require.Equal(t, tc.DIDKey, didKey)
			require.Equal(t, tc.DIDKeyID, keyID)
		})
	}

	t.Run("nil input", func(t *testing.T) {
		_, _, err := CreateDIDKeyByJwk(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "jsonWebKey is required")
	})

	t.Run("test invalid type", func(t *testing.T) {
		jwkKey := jwk.JWK{
			Kty: "XX",
			Crv: elliptic.P256().Params().Name,
		}
		_, _, err := CreateDIDKeyByJwk(&jwkKey)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported kty")
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

func TestDIDKeyX25519(t *testing.T) {
	const (
		x25519DIDKey = "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F"
		x25519Base58 = "4Dy8E9UaZscuPUf2GLxV44RCNL7oxmEXXkgWXaug1WKV"
		keyIDX25519  = "did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F#z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F" //nolint:lll
	)

	didKey, keyID := CreateDIDKeyByCode(X25519PubKeyMultiCodec, base58.Decode(x25519Base58))

	require.Equal(t, x25519DIDKey, didKey)
	require.Equal(t, keyID, keyIDX25519)

	pubKey, err := PubKeyFromDIDKey(x25519DIDKey)
	require.NoError(t, err)
	require.Equal(t, x25519Base58, base58.Encode(pubKey))
}

func TestPubKeyFromDIDKeyFailure(t *testing.T) {
	_, err := PubKeyFromDIDKey("did:key:****")
	require.EqualError(t, err, "pubKeyFromDIDKey: MethodIDFromDIDKey: not a valid did:key identifier "+
		"(not a base58btc multicodec): did:key:****")
}
