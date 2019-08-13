/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

func TestEncrypt(t *testing.T) {
	var err error
	// create temporary keys for testing
	sendEcKey := keyPair{}
	sendEcKey.pub, sendEcKey.priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)

	recipient1Key := keyPair{}
	recipient1Key.pub, recipient1Key.priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)

	recipient2Key := keyPair{}
	recipient2Key.pub, recipient2Key.priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)

	recipient3Key := keyPair{}
	recipient3Key.pub, recipient3Key.priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)

	badKey := keyPair{
		pub:  nil,
		priv: nil,
	}
	t.Run("Error test case: Create a new AuthCrypter with bad encryption algorithm", func(t *testing.T) {
		_, e := New(sendEcKey, []*[chacha20poly1305.KeySize]byte{recipient1Key.pub, recipient2Key.pub, recipient3Key.pub}, "BAD")
		require.Error(t, e)
	})

	t.Run("Error test case: Create a new AuthCrypter with bad sender key", func(t *testing.T) {
		_, e := New(badKey, []*[chacha20poly1305.KeySize]byte{recipient1Key.pub, recipient2Key.pub, recipient3Key.pub}, XC20P)
		require.Error(t, e)
	})

	t.Run("Error test case: Create a new AuthCrypter with bad recipient key", func(t *testing.T) {
		_, e := New(sendEcKey, []*[chacha20poly1305.KeySize]byte{}, "XC20P")
		require.Error(t, e)
	})

	t.Run("Success test case: Create a valid AuthCrypter for ChachaPoly1035 encryption (alg: C20P)", func(t *testing.T) {
		crypter, e := New(sendEcKey, []*[chacha20poly1305.KeySize]byte{recipient1Key.pub, recipient2Key.pub, recipient3Key.pub}, C20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"))
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with C20P: %s", m)
	})

	t.Run("Success test case: Create a valid AuthCrypter for XChachaPoly1035 encryption (alg: XC20P)", func(t *testing.T) {
		crypter, e := New(sendEcKey, []*[chacha20poly1305.KeySize]byte{recipient1Key.pub, recipient2Key.pub, recipient3Key.pub}, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"))
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with XC20P: %s", m)

		t.Run("Error test Case: use a valid AuthCrypter but scramble the nonce size", func(t *testing.T) {
			crypter.nonceSize = 0
			_, err = crypter.Encrypt([]byte("lorem ipsum dolor sit amet"))
			require.Error(t, err)
		})
	})

	// TODO add Decrypt test cases once implemented
	t.Run("Error test Case [INCOMPLETE]: Test Decrypting a message should fail as it's not implemented yet", func(t *testing.T) {
		crypter, e := New(sendEcKey, []*[chacha20poly1305.KeySize]byte{recipient1Key.pub, recipient2Key.pub, recipient3Key.pub}, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"))
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with XC20P: %s", m)

		dec, e := crypter.Decrypt(enc, recipient1Key.priv)
		require.Error(t, e)
		require.Empty(t, dec)
	})

}

func prettyPrint(msg []byte) (string, error) {
	var prettyJSON bytes.Buffer
	err := json.Indent(&prettyJSON, msg, "", "\t")
	if err != nil {
		return "", err
	}

	return prettyJSON.String(), nil
}

func TestBadCreateCipher(t *testing.T) {
	_, err := createCipher(0, nil)
	require.Error(t, err)
}

func TestRefEncrypt(t *testing.T) {
	// reference from
	// https://github.com/hyperledger/aries-rfcs/issues/133#issuecomment-518922447
	var senderPriv = "6tsNPgZAg-NWM3s4S0VOOWM2yrcOfwsCrN0JGFEWaWw"
	var senderPub = "QbvqozxGQ3U8FDLmlKOx8Hd5GiozMRO2pwrevZ5ZFTM"
	var recipientPub = "-u0zk9iY_ZS2wP2z4zuLjR7_kz_kxVU0anRz8_A66T0"
	var payload = []byte("SGVsbG8gV29ybGQh")

	var refJWE = `{
    "protected": "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1tZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
    "recipients": [
        {
            "encrypted_key": "Y6eYXyrOWj67oHh4hla_MS024oPtgWeM4LOPqwyrXTM",
            "header": {
                "apu": "MMapegFCsTTrygbuC80X0NeHjrtJ7Fh5d9CIl6pq4HVgYDAtjIS7dyQKXO-Vgan8ho33ZglRJCfW4Wx2pH3cNg",
                "iv": "eBuzpjLTU16gmJvZKV3JShzvibJM6h7_",
                "tag": "PKg4RLQ5hikKQ2Vq2SCqGg",
                "kid": "HtWhz6QevaQF39Gv3Hvf7K6xo2FTViAkY22rhZpQrdWc",
                "oid": "cOvRYUooq-y1TDjK3Lt3wCA3H-w9E6PJXNPDdIPLDDZlpE7QJvJuLIwJzSPqDhRvQUMaOYrXyLGAgdriGpKbKjWcLtQapjExq8sesL5bax68J46vv-2-GuDVbQ"
            }
        }
    ],
    "aad": "FeI0LXy7m0-orE0VwiQU-2RjQyYMsnIvSEzpduiB7sY",
    "iv": "9AL-EASXKfuonBKKxsPHSccrX2zy7j2l",
    "tag": "IG6L99-sFnq3Cfz29Z-jDg",
    "ciphertext": "IX7EQSrqhxL61YjE"
}`

	senderPrivK := &[32]byte{}
	copy(senderPrivK[:], senderPriv)
	senderPubK := &[32]byte{}
	copy(senderPubK[:], senderPub)
	senderKp := keyPair{
		priv: senderPrivK,
		pub:  senderPubK,
	}
	recipientPubK := &[32]byte{}
	copy(recipientPubK[:], recipientPub)

	crypter, err := New(senderKp, []*[32]byte{recipientPubK}, XC20P)
	require.NoError(t, err)
	require.NotNil(t, crypter)

	pld, err := crypter.Encrypt(payload)
	require.NoError(t, err)

	refPld, err := prettyPrint([]byte(refJWE))
	require.NoError(t, err)
	encryptedPld, err := prettyPrint(pld)
	require.NoError(t, err)
	t.Logf("Reference JWE: %s", refPld)
	t.Logf("Encrypted JWE: %s", encryptedPld)
	var refPldUnmarshalled Envelope
	err = json.Unmarshal([]byte(refJWE), &refPldUnmarshalled)
	require.NoError(t, err)
	var encryptedPldUmarshalled Envelope
	err = json.Unmarshal(pld, &encryptedPldUmarshalled)
	require.NoError(t, err)
	t.Logf("Reference JWE Ummarshalled: %s", refPldUnmarshalled)
	t.Logf("Encrypted JWE Ummarshalled: %s", encryptedPldUmarshalled)
}
