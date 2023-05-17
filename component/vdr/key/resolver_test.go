/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package key

import (
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/doc/util/fingerprint"
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

	t.Run("validate an invalid did method", func(t *testing.T) {
		v := New()

		doc, err := v.Read("did:invalid:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH")
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid did:key method: invalid")
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

func readBigInt(t *testing.T, b64 string) *big.Int {
	buf, err := base64.RawURLEncoding.DecodeString(b64)
	require.Nil(t, err, "can't parse string as b64: %v\n%s", err, b64)

	var x big.Int
	x = *x.SetBytes(buf)

	return &x
}

func TestReadP256(t *testing.T) {
	v := New()

	const (
		k1    = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv"
		k1KID = "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv#zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv" //nolint:lll
		k1X   = "igrFmi0whuihKnj9R3Om1SoMph72wUGeFaBbzG2vzns"
		k1Y   = "efsX5b10x8yjyrj4ny3pGfLcY7Xby1KzgqOdqnsrJIM"
		k2    = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"
		k2KID = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169" //nolint:lll
		k2X   = "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI"
		k2Y   = "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)
		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k1, k1KID, elliptic.P256(),
			readBigInt(t, k1X), readBigInt(t, k1Y))
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k2, k2KID, elliptic.P256(),
			readBigInt(t, k2X), readBigInt(t, k2Y))
	})
}

func TestReadP384(t *testing.T) {
	v := New()

	const (
		k1    = "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9"                                                                         //nolint:lll
		k1KID = "did:key:z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9#z82Lm1MpAkeJcix9K8TMiLd5NMAhnwkjjCBeWHXyu3U4oT2MVJJKXkcVBgjGhnLBn2Kaau9" //nolint:lll
		k1X   = "lInTxl8fjLKp_UCrxI0WDklahi-7-_6JbtiHjiRvMvhedhKVdHBfi2HCY8t_QJyc"
		k1Y   = "y6N1IC-2mXxHreETBW7K3mBcw0qGr3CWHCs-yl09yCQRLcyfGv7XhqAngHOu51Zv"
		k2    = "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54"                                                                         //nolint:lll
		k2KID = "did:key:z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54#z82LkvCwHNreneWpsgPEbV3gu1C6NFJEBg4srfJ5gdxEsMGRJUz2sG9FE42shbn2xkZJh54" //nolint:lll
		k2X   = "CA-iNoHDg1lL8pvX3d1uvExzVfCz7Rn6tW781Ub8K5MrDf2IMPyL0RTDiaLHC1JT"
		k2Y   = "Kpnrn8DkXUD3ge4mFxi-DKr0DYO2KuJdwNBrhzLRtfMa3WFMZBiPKUPfJj8dYNl_"
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)
		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k1, k1KID, elliptic.P384(),
			readBigInt(t, k1X), readBigInt(t, k1Y))
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k2, k2KID, elliptic.P384(),
			readBigInt(t, k2X), readBigInt(t, k2Y))
	})
}

func TestRead521(t *testing.T) {
	v := New()

	const (
		k1    = "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7"                                                                                                  //nolint:lll
		k1KID = "did:key:z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7#z2J9gaYxrKVpdoG9A4gRnmpnRCcxU6agDtFVVBVdn1JedouoZN7SzcyREXXzWgt3gGiwpoHq7K68X4m32D8HgzG8wv3sY5j7" //nolint:lll
		k1X   = "ASUHPMyichQ0QbHZ9ofNx_l4y7luncn5feKLo3OpJ2nSbZoC7mffolj5uy7s6KSKXFmnNWxGJ42IOrjZ47qqwqyS"
		k1Y   = "AW9ziIC4ZQQVSNmLlp59yYKrjRY0_VqO-GOIYQ9tYpPraBKUloEId6cI_vynCzlZWZtWpgOM3HPhYEgawQ703RjC"
		k2    = "did:key:z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f"                                                                                                  //nolint:lll
		k2KID = "did:key:z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f#z2J9gcGdb2nEyMDmzQYv2QZQcM1vXktvy1Pw4MduSWxGabLZ9XESSWLQgbuPhwnXN7zP7HpTzWqrMTzaY5zWe6hpzJ2jnw4f" //nolint:lll
		k2X   = "AQgyFy6EwH3_u_KXPw8aTXTY7WSVytmbuJeFpq4U6LipxtSmBJe_jjRzms9qubnwm_fGoHMQlvQ1vzS2YLusR2V0"
		k2Y   = "Ab06MCcgoG7dM2I-VppdLV1k3lDoeHMvyYqHVfP05Ep2O7Zu0Qwd6IVzfZi9K0KMDud22wdnGUpUtFukZo0EeO15"
	)

	t.Run("key 1", func(t *testing.T) {
		docResolution, err := v.Read(k1)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)
		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k1, k1KID, elliptic.P521(),
			readBigInt(t, k1X), readBigInt(t, k1Y))
	})

	t.Run("key 2", func(t *testing.T) {
		docResolution, err := v.Read(k2)
		require.NoError(t, err)
		require.NotNil(t, docResolution.DIDDocument)

		assertJSONWebKeyDoc(t, docResolution.DIDDocument, k2, k2KID, elliptic.P521(),
			readBigInt(t, k2X), readBigInt(t, k2Y))
	})
}

func TestCreateJsonWeKey(t *testing.T) {
	t.Run("test invalid code", func(t *testing.T) {
		_, err := createJSONWebKey2020DIDDoc("123", 0, []byte{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported key multicodec code for JsonWebKey2020")
	})

	t.Run("test invalid key bytes", func(t *testing.T) {
		_, err := createJSONWebKey2020DIDDoc("123", fingerprint.P256PubKeyMultiCodec, []byte{0x01})
		require.Error(t, err)
		require.Contains(t, err.Error(), "error unmarshalling key bytes")
	})
}
