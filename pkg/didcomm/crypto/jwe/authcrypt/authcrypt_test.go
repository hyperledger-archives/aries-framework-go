/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"

	jwecrypto "github.com/hyperledger/aries-framework-go/pkg/didcomm/crypto"
)

func TestEncrypt(t *testing.T) {
	var err error
	// create temporary keys for testing
	sendEcKey := jwecrypto.KeyPair{}
	sendEcKey.Pub, sendEcKey.Priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)
	t.Logf("sender key pub: %v", base64.RawURLEncoding.EncodeToString(sendEcKey.Pub[:]))
	t.Logf("sender key priv: %v", base64.RawURLEncoding.EncodeToString(sendEcKey.Priv[:]))

	recipient1Key := jwecrypto.KeyPair{}
	recipient1Key.Pub, recipient1Key.Priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)
	t.Logf("recipient1Key pub: %v", base64.RawURLEncoding.EncodeToString(recipient1Key.Pub[:]))
	t.Logf("recipient1Key priv: %v", base64.RawURLEncoding.EncodeToString(recipient1Key.Priv[:]))

	recipient2Key := jwecrypto.KeyPair{}
	recipient2Key.Pub, recipient2Key.Priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)
	t.Logf("recipient2Key pub: %v", base64.RawURLEncoding.EncodeToString(recipient2Key.Pub[:]))
	t.Logf("recipient2Key priv: %v", base64.RawURLEncoding.EncodeToString(recipient2Key.Priv[:]))

	recipient3Key := jwecrypto.KeyPair{}
	recipient3Key.Pub, recipient3Key.Priv, err = box.GenerateKey(randReader)
	require.NoError(t, err)
	t.Logf("recipient3Key pub: %v", base64.RawURLEncoding.EncodeToString(recipient3Key.Pub[:]))
	t.Logf("recipient3Key priv: %v", base64.RawURLEncoding.EncodeToString(recipient3Key.Priv[:]))

	badKey := jwecrypto.KeyPair{
		Pub:  nil,
		Priv: nil,
	}

	t.Run("Error test case: Create a new AuthCrypter with bad encryption algorithm", func(t *testing.T) {
		_, e := New("BAD")
		require.Error(t, e)
		require.EqualError(t, e, errUnsupportedAlg.Error())
	})

	t.Run("Error test case: Create a new AuthCrypter and use a bad sender key for encryption", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"),
			badKey, []*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.Error(t, e)
		require.Empty(t, enc)
	})

	t.Run("Error test case: Create a new AuthCrypter and use an empty recipient keys list for encryption", func(t *testing.T) { //nolint:lll
		crypter, e := New("XC20P")
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"), sendEcKey, []*[chacha.KeySize]byte{})
		require.Error(t, e)
		require.Empty(t, enc)
	})

	t.Run("Success test case: Create a valid AuthCrypter for ChachaPoly1035 encryption (alg: C20P)", func(t *testing.T) {
		crypter, e := New(C20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"),
			sendEcKey, []*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with C20P: %s", m)
	})

	t.Run("Success test case: Create a valid AuthCrypter for XChachaPoly1035 encryption (alg: XC20P)", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("lorem ipsum dolor sit amet"),
			sendEcKey, []*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with XC20P: %s", m)

		t.Run("Error test Case: use a valid AuthCrypter but scramble the nonce size", func(t *testing.T) {
			crypter.nonceSize = 0
			_, err = crypter.Encrypt([]byte("lorem ipsum dolor sit amet"),
				sendEcKey, []*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
			require.Error(t, err)
		})
	})

	t.Run("Success test case: Decrypting a message (with the same crypter)", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := crypter.Encrypt(pld, sendEcKey,
			[]*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// decrypt for recipient1
		dec, e := crypter.Decrypt(enc, recipient1Key)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)
	})

	t.Run("Success test case: Decrypting a message with two Crypter instances to simulate two agents", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := crypter.Encrypt(pld, sendEcKey,
			[]*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// now decrypt with recipient3
		crypter1, e := New(XC20P)
		require.NoError(t, e)
		dec, e := crypter1.Decrypt(enc, recipient3Key)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)

		// now try decrypting with recipient2
		crypter2, e := New(XC20P)
		require.NoError(t, e)
		dec, e = crypter2.Decrypt(enc, recipient2Key)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)
		t.Logf("Decryption Payload with XC20P: %s", pld)
	})

	t.Run("Failure test case: Decrypting a message with an unauthorized (recipient2) agent", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := crypter.Encrypt(pld, sendEcKey, []*[chacha.KeySize]byte{recipient1Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// decrypting for recipient 2 (unauthorized)
		crypter1, e := New(XC20P)
		require.NoError(t, e)
		dec, e := crypter1.Decrypt(enc, recipient2Key)
		require.Error(t, e)
		require.Empty(t, dec)

		// now try to decrypt with an invalid recipient who's trying to use another agent's key
		crypter1, e = New(XC20P)
		require.NoError(t, e)
		dec, e = crypter1.Decrypt(enc, jwecrypto.KeyPair{Priv: recipient2Key.Priv, Pub: recipient1Key.Pub})
		require.Error(t, e)
		require.Empty(t, dec)
	})

	t.Run("Failure test case: Decrypting a message but scramble JWE beforehand", func(t *testing.T) {
		crypter, e := New(XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := crypter.Encrypt(pld, sendEcKey,
			[]*[chacha.KeySize]byte{recipient1Key.Pub, recipient2Key.Pub, recipient3Key.Pub})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		var validJwe *Envelope
		e = json.Unmarshal(enc, &validJwe)
		require.NoError(t, e)

		// make a jwe copy to test with scrambling its values
		jwe := &Envelope{}
		deepCopy(jwe, validJwe)

		// test decrypting with empty recipient key
		dec, e := crypter.Decrypt(enc, jwecrypto.KeyPair{Priv: recipient1Key.Priv, Pub: &[chacha.KeySize]byte{}})
		require.EqualError(t, e, fmt.Sprintf("failed to decrypt message: %s", errRecipientNotFound.Error()))
		require.Empty(t, dec)

		// test bad jwe format
		enc = []byte("{badJWE}")

		// update jwe with bad cipherText format
		jwe.CipherText = "badCipherText"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce format
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt message: illegal base64 data at input byte 12")
		require.Empty(t, dec)
		jwe.CipherText = validJwe.CipherText

		// update jwe with bad nonce format
		jwe.IV = "badIV!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce format
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt message: illegal base64 data at input byte 5")
		require.Empty(t, dec)
		jwe.IV = validJwe.IV

		// update jwe with bad tag format
		jwe.Tag = "badTag!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag format
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt message: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Tag = validJwe.Tag

		// update jwe with bad aad format
		jwe.AAD = "badAAD"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt message: failed to decrypt message - invalid AAD in envelope")
		require.Empty(t, dec)
		jwe.AAD = validJwe.AAD

		// update jwe with bad recipient oid format
		jwe.Recipients[0].Header.OID = "badOID!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt message: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.OID = validJwe.Recipients[0].Header.OID

		// update jwe with bad recipient tag format
		jwe.Recipients[0].Header.Tag = "badTag!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.Tag = validJwe.Recipients[0].Header.Tag

		// update jwe with bad recipient nonce format
		jwe.Recipients[0].Header.IV = "badIV!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: illegal base64 data at input byte 5")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.IV = validJwe.Recipients[0].Header.IV

		// update jwe with bad recipient apu format
		jwe.Recipients[0].Header.APU = "badAPU!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.APU = validJwe.Recipients[0].Header.APU

		// update jwe with bad recipient kid (sender) format
		jwe.Recipients[0].Header.KID = "badKID!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, fmt.Sprintf("failed to decrypt message: %s", errRecipientNotFound.Error()))
		require.Empty(t, dec)
		jwe.Recipients[0].Header.KID = validJwe.Recipients[0].Header.KID

		// update jwe with bad recipient CEK (encrypted key) format
		jwe.Recipients[0].EncryptedKey = "badEncryptedKey!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: illegal base64 data at input byte 15")
		require.Empty(t, dec)
		jwe.Recipients[0].EncryptedKey = validJwe.Recipients[0].EncryptedKey

		// update jwe with bad recipient CEK (encrypted key) value
		jwe.Recipients[0].EncryptedKey = "Np2ZIsTdsM190yv_v3FkfjVshGqAUvH4KfWOnQE8wl4"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: chacha20poly1305: message authentication failed")
		require.Empty(t, dec)
		jwe.Recipients[0].EncryptedKey = validJwe.Recipients[0].EncryptedKey

		// now try bad nonce size
		jwe.IV = "ouaN1Qm8cUzNr1IC"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce value
		require.PanicsWithValue(t, "chacha20poly1305: bad nonce length passed to Open", func() {
			dec, e = crypter.Decrypt(enc, recipient1Key)
		})
		require.Empty(t, dec)
		jwe.IV = validJwe.IV

		// now try bad nonce value
		jwe.Recipients[0].Header.IV = "dZY1WrG0IeIOfLJG8FMLkf3BUqUCe0xI"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = crypter.Decrypt(enc, recipient1Key)
		require.EqualError(t, e, "failed to decrypt shared key: chacha20poly1305: message authentication failed")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.IV = validJwe.Recipients[0].Header.IV
	})
}

func deepCopy(envelope, envelope2 *Envelope) {
	for _, r := range envelope2.Recipients {
		newRe := Recipient{
			EncryptedKey: r.EncryptedKey,
			Header: RecipientHeaders{
				APU: r.Header.APU,
				KID: r.Header.KID,
				IV:  r.Header.IV,
				OID: r.Header.OID,
				Tag: r.Header.Tag,
			},
		}
		envelope.Recipients = append(envelope.Recipients, newRe)
	}
	envelope.CipherText = envelope2.CipherText
	envelope.IV = envelope2.IV
	envelope.Protected = envelope2.Protected
	envelope.AAD = envelope2.AAD
	envelope.Tag = envelope2.Tag
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
	// reference php crypto material similar to
	// https://github.com/hyperledger/aries-rfcs/issues/133#issuecomment-518922447
	var senderPrivStr = "XZOBB1M7ikDoFR86rSgAuVt1ACJDMJ9alxHUsND6MBo"
	senderPriv, err := base64.RawURLEncoding.DecodeString(senderPrivStr)
	require.NoError(t, err)
	var senderPubStr = "qdXzr6z28ck-RfTEiaBZmHOwH11ow-CBfLo97Qe31j4"
	senderPub, err := base64.RawURLEncoding.DecodeString(senderPubStr)
	require.NoError(t, err)
	var recipientPrivStr = "kE3RDpviO_lVI3hdi6CKfT2BbuPph4WjC2DnkX7fBz4"
	recipientPriv, err := base64.RawURLEncoding.DecodeString(recipientPrivStr)
	require.NoError(t, err)
	var recipientPubStr = "800RcOPc9M8vFElpaHGkl-p9SpmY2Efm2MZW5tikf1c"
	recipientPub, err := base64.RawURLEncoding.DecodeString(recipientPubStr)
	require.NoError(t, err)
	var payloadStr = "SGVsbG8gV29ybGQh"
	payload, err := base64.RawURLEncoding.DecodeString(payloadStr)
	require.NoError(t, err)

	// refJWE created by executing PHP test code at:
	// https://github.com/gamringer/php-authcrypt/blob/master/examples/1-crypt.php
	//nolint:lll
	const refJWE = `{
    "protected": "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1tZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
    "recipients": [
        {
            "encrypted_key": "-MXYFTdqmcmw11apipgtcr-E365Yvk6_4d9cVxRs89U",
            "header": {
                "apu": "cJn0DhdOCZAmuLCFuOM1R9v26aPVl-EMW5V_Y81zgkddrzw2WmAvdSbhrS0BHjAmRdsZ52fPYoveQZeQIIFqPw",
                "iv": "s2rbhR-abOcLdJuZpvKLa_aLfhIqRyGL",
                "tag": "vx1JrepSfW90QIbG7vRBWg",
                "kid": "HNkELiimfV5S3VyMWVqCd6H77cE3FMhYgp2Gq4tvZRJn",
                "oid": "KStwoVefDEH4gsdTQay0QyLkPMtXdJPJhMrO9hk-A0-cKE5sqBZxAIc4_iw7VOaSRLCMipZgYWD1epH1hQJbUMESQtuGUBCxVZCAJJYQNML7PtZz1wooCYyBfa4"
            }
        }
    ],
    "aad": "xuT9nzr1gf7k9IlS2936LFnUoDb-Tu1cBa8fhfUgxGk",
    "iv": "nM0UDDCERek5syITAHwzDPGiEVErTtpo",
    "tag": "gu1ZvF35-JYMd1JITD0qeg",
    "ciphertext": "ntZwQokGaZhnQ8L2"
}`

	senderPrivK := &[32]byte{}
	copy(senderPrivK[:], senderPriv)
	senderPubK := &[32]byte{}
	copy(senderPubK[:], senderPub)
	senderKp := jwecrypto.KeyPair{
		Priv: senderPrivK,
		Pub:  senderPubK,
	}
	recipientPubK := &[32]byte{}
	copy(recipientPubK[:], recipientPub)

	crypter, err := New(XC20P)
	require.NoError(t, err)
	require.NotNil(t, crypter)

	pld, err := crypter.Encrypt(payload, senderKp, []*[32]byte{recipientPubK})
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

	// try to decrypt the encrypted payload
	recipientPrivK := &[32]byte{}
	copy(recipientPrivK[:], recipientPriv)
	dec, err := crypter.Decrypt(pld, jwecrypto.KeyPair{Priv: recipientPrivK, Pub: recipientPubK})
	require.NoError(t, err)
	require.NotEmpty(t, dec)
	require.Equal(t, dec, payload)

	// TODO fix try to decrypt the reference payload
	// dec, err = crypter.Decrypt([]byte(refJWE), recipientPrivK, []*[32]byte{recipientPubK})
	// require.NoError(t, err)
	// require.NotEmpty(t, dec)
}
