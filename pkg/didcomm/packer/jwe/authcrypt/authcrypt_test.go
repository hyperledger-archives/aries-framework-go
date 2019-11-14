/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
)

func TestEncodingType(t *testing.T) {
	// create temporary signing keys for tests
	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err := mockkms.GenerateRawKeys(rand.Reader)
	require.NoError(t, err)

	_, ks := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	kmsProvider, err := mockkms.NewMockProvider(ks)
	require.NoError(t, err)

	packer, e := New(kmsProvider, XC20P)
	require.NoError(t, e)
	require.NotEmpty(t, packer)

	require.Equal(t, encodingType, packer.EncodingType())
}

func TestEncrypt(t *testing.T) {
	var err error
	// create temporary signing keys for tests - for sender
	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err := mockkms.GenerateRawKeys(rand.Reader)
	require.NoError(t, err)

	senderSigPubKey, senderKeySet := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	t.Logf("sender Signature key pub: %v", base64.RawURLEncoding.EncodeToString(sigPubKey))
	t.Logf("sender Signature key priv: %v", base64.RawURLEncoding.EncodeToString(sigPrivKey))
	t.Logf("sender Encryption key pub: %v", base64.RawURLEncoding.EncodeToString(encPubKey))
	t.Logf("sender Encryption key priv: %v", base64.RawURLEncoding.EncodeToString(encPrivKey))

	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err = mockkms.GenerateRawKeys(rand.Reader)

	rec1SigPubKey, rec1KeySet := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	t.Logf("rec1 Sig key pub: %v", base64.RawURLEncoding.EncodeToString(sigPubKey))
	t.Logf("rec1 Sig key priv: %v", base64.RawURLEncoding.EncodeToString(sigPrivKey))
	t.Logf("rec1 Enc pub: %v", base64.RawURLEncoding.EncodeToString(encPubKey))
	t.Logf("rec1 Enc priv: %v", base64.RawURLEncoding.EncodeToString(encPrivKey))

	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err = mockkms.GenerateRawKeys(rand.Reader)
	require.NoError(t, err)

	rec2SigPubKey, rec2KeySet := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	t.Logf("rec2 Sig key pub: %v", base64.RawURLEncoding.EncodeToString(sigPubKey))
	t.Logf("rec2 Sig key priv: %v", base64.RawURLEncoding.EncodeToString(sigPrivKey))
	t.Logf("rec2 Enc pub: %v", base64.RawURLEncoding.EncodeToString(encPubKey))
	t.Logf("rec2 Enc priv: %v", base64.RawURLEncoding.EncodeToString(encPrivKey))

	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err = mockkms.GenerateRawKeys(rand.Reader)
	require.NoError(t, err)

	rec3SigPubKey, rec3KeySet := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	t.Logf("rec3 Sig key pub: %v", base64.RawURLEncoding.EncodeToString(sigPubKey))
	t.Logf("rec3 Sig key priv: %v", base64.RawURLEncoding.EncodeToString(sigPrivKey))
	t.Logf("rec3 Enc pub: %v", base64.RawURLEncoding.EncodeToString(encPubKey))
	t.Logf("rec3 Enc priv: %v", base64.RawURLEncoding.EncodeToString(encPrivKey))

	allKMSProvider, err := mockkms.NewMockProvider(senderKeySet, rec1KeySet, rec2KeySet, rec3KeySet)
	require.NoError(t, err)
	senderKMSProvider, err := mockkms.NewMockProvider(senderKeySet)
	require.NoError(t, err)
	recipient1KMSProvider, err := mockkms.NewMockProvider(rec1KeySet)
	require.NoError(t, err)
	recipient2KMSProvider, err := mockkms.NewMockProvider(rec2KeySet)
	require.NoError(t, err)
	recipient3KMSProvider, err := mockkms.NewMockProvider(rec3KeySet)
	require.NoError(t, err)

	badKey := cryptoutil.Key{
		ID: "badID",
	}

	t.Run("Error test case: Create a new AuthCrypt PackerValue with bad encryption algorithm", func(t *testing.T) {
		_, e := New(senderKMSProvider, "BAD")
		require.Error(t, e)
		require.EqualError(t, e, errUnsupportedAlg.Error())
	})

	t.Run("Error test case: Create a new AuthCrypt PackerValue and use an empty keys for encryption", func(t *testing.T) {
		packer, e := New(senderKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		badKey.Value = ""
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		enc, e := packer.Pack(
			[]byte("lorem ipsum dolor sit amet"),
			[]byte(badKey.Value),
			[][]byte{rec1Key, rec2Key, rec3Key})
		require.EqualError(t, e, "failed to pack message: empty sender key")
		require.Empty(t, enc)
	})

	t.Run("Error test case: Create a new AuthCrypt PackerValue and use a bad key for encryption", func(t *testing.T) {
		packer, e := New(senderKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		// test bad sender public key
		badKey.Value = "badkey"
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"),
			[]byte(badKey.Value), [][]byte{rec1Key, rec2Key, rec3Key})
		require.EqualError(t, e, "key not found")
		require.Empty(t, enc)

		// reset badKey
		badKey.Value = ""

		// test bad recipient 1 public key size
		enc, e = packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{[]byte("badkeysize"), rec2Key, rec3Key})
		require.EqualError(t, e, "failed to pack message: invalid key - for recipient 1")
		require.Empty(t, enc)
		// test bad recipient 2 public key size
		enc, e = packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{rec1Key, []byte("badkeysize"), rec3Key})
		require.EqualError(t, e, "failed to pack message: invalid key - for recipient 2")
		require.Empty(t, enc)
		// test bad recipient 3 publick key size
		enc, e = packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{rec1Key, rec2Key, []byte("badkeysize")})
		require.EqualError(t, e, "failed to pack message: invalid key - for recipient 3")
		require.Empty(t, enc)

		// test invalid recipient 1 key
		k, e := base64.RawURLEncoding.DecodeString("-----vh1JG9hO0123pO3gWyngGwLivn32PzUdUDwW4w")
		require.NoError(t, e)

		enc, e = packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{k, rec2Key, rec3Key})
		require.EqualError(t, e, "failed to pack message: error converting public key")
		require.Empty(t, enc)
	})

	t.Run("Error test case: Create a new AuthCrypt PackerValue and use an empty recipient keys list for encryption", func(t *testing.T) { //nolint:lll
		packer, e := New(senderKMSProvider, "XC20P")
		require.NoError(t, e)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		require.NotEmpty(t, packer)
		enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"), senderKey, [][]byte{})
		require.EqualError(t, e, "failed to pack message: empty recipients")
		require.Empty(t, enc)
	})

	t.Run("Success test case: Create a valid PackerValue for ChachaPoly1305 encryption (alg: C20P)", func(t *testing.T) {
		packer, e := New(allKMSProvider, C20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with C20P: %s", m)
	})

	t.Run("Success test case: Create a valid PackerValue for XChachaPoly1305 encryption (alg: XC20P)", func(t *testing.T) {
		packer, e := New(allKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		// test invalid recipient 1 key
		k, e := base64.RawURLEncoding.DecodeString("-----vh1JG9hO0123pO3gWyngGwLivn32PzUdUDwW4w")
		require.NoError(t, e)

		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"),
			senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		enc, e = packer.Pack([]byte("lorem ipsum dolor sit amet"), senderKey, [][]byte{k, rec2Key, rec3Key})
		require.EqualError(t, e, "failed to pack message: error converting public key")
		require.Empty(t, enc)
	})

	t.Run("Error test case: Create a new AuthCrypter and use an empty recipient keys list for encryption",
		func(t *testing.T) {
			packer, e := New(senderKMSProvider, "XC20P")
			require.NoError(t, e)
			require.NotEmpty(t, packer)
			senderKey := base58.Decode(senderSigPubKey.Value)
			require.NotEmpty(t, senderKey)
			enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"), senderKey, [][]byte{})
			require.EqualError(t, e, "failed to pack message: empty recipients")
			require.Empty(t, enc)
		})

	t.Run("Success test case: Create a valid AuthCrypter for ChachaPoly1305 encryption (alg: C20P)",
		func(t *testing.T) {
			packer, e := New(allKMSProvider, C20P)
			require.NoError(t, e)
			require.NotEmpty(t, packer)
			rec1Key := base58.Decode(rec1SigPubKey.Value)
			require.NotEmpty(t, rec1Key)
			rec2Key := base58.Decode(rec2SigPubKey.Value)
			require.NotEmpty(t, rec2Key)
			rec3Key := base58.Decode(rec3SigPubKey.Value)
			require.NotEmpty(t, rec3Key)
			senderKey := base58.Decode(senderSigPubKey.Value)
			require.NotEmpty(t, senderKey)
			enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"), senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
			require.NoError(t, e)
			require.NotEmpty(t, enc)

			m, e := prettyPrint(enc)
			require.NoError(t, e)
			t.Logf("Encryption with C20P: %s", m)
		})

	t.Run("Success test case: Create a valid AuthCrypter for XChachaPoly1305 encryption (alg: XC20P)",
		func(t *testing.T) {
			packer, e := New(allKMSProvider, XC20P)
			require.NoError(t, e)
			require.NotEmpty(t, packer)
			rec1Key := base58.Decode(rec1SigPubKey.Value)
			require.NotEmpty(t, rec1Key)
			rec2Key := base58.Decode(rec2SigPubKey.Value)
			require.NotEmpty(t, rec2Key)
			rec3Key := base58.Decode(rec3SigPubKey.Value)
			require.NotEmpty(t, rec3Key)
			senderKey := base58.Decode(senderSigPubKey.Value)
			require.NotEmpty(t, senderKey)
			enc, e := packer.Pack([]byte("lorem ipsum dolor sit amet"), senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
			require.NoError(t, e)
			require.NotEmpty(t, enc)

			m, e := prettyPrint(enc)
			require.NoError(t, e)
			t.Logf("Encryption with XC20P: %s", m)

			t.Run("Error test Case: use a valid AuthCrypter but scramble the nonce size", func(t *testing.T) {
				packer.nonceSize = 0
				_, err = packer.Pack([]byte("lorem ipsum dolor sit amet"),
					senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
				require.Error(t, err)
			})
		})

	t.Run("Success test case: Decrypting a message (with the same packer)", func(t *testing.T) {
		// not a real life scenario, the kms is using both sender and rec1 key pairs
		// allKMSProvider is used here for testing purposes only
		packer, e := New(allKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := packer.Pack(pld, senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// decrypt for rec1 (as found in kms)
		dec, e := packer.Unpack(enc)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)
	})

	t.Run("Success test case: Decrypting a message with two PackerValue instances to simulate two agents", func(t *testing.T) { //nolint:lll
		// encrypt with sender
		packer, e := New(allKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := packer.Pack(pld, senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// now decrypt with recipient3
		packer1, e := New(recipient3KMSProvider, XC20P)
		require.NoError(t, e)
		dec, e := packer1.Unpack(enc)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)

		// now try decrypting with recipient2
		packer2, e := New(recipient2KMSProvider, XC20P)
		require.NoError(t, e)
		dec, e = packer2.Unpack(enc)
		require.NoError(t, e)
		require.NotEmpty(t, dec)
		require.EqualValues(t, dec, pld)
		t.Logf("Decryption Payload with XC20P: %s", pld)
	})

	t.Run("Failure test case: Decrypting a message with an unauthorized (recipient2) agent", func(t *testing.T) {
		packer, e := New(allKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := packer.Pack(pld, senderKey, [][]byte{rec1Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		m, e := prettyPrint(enc)
		require.NoError(t, e)
		t.Logf("Encryption with unescaped XC20P: %s", enc)
		t.Logf("Encryption with XC20P: %s", m)

		// decrypting for recipient 2 (unauthorized)
		packer1, e := New(recipient2KMSProvider, XC20P)
		require.NoError(t, e)
		dec, e := packer1.Unpack(enc)
		require.Error(t, e)
		require.Empty(t, dec)
	})

	t.Run("Failure test case: Decrypting a message but scramble JWE beforehand", func(t *testing.T) {
		packer, e := New(allKMSProvider, XC20P)
		require.NoError(t, e)
		require.NotEmpty(t, packer)
		rec1Key := base58.Decode(rec1SigPubKey.Value)
		require.NotEmpty(t, rec1Key)
		rec2Key := base58.Decode(rec2SigPubKey.Value)
		require.NotEmpty(t, rec2Key)
		rec3Key := base58.Decode(rec3SigPubKey.Value)
		require.NotEmpty(t, rec3Key)
		senderKey := base58.Decode(senderSigPubKey.Value)
		require.NotEmpty(t, senderKey)
		pld := []byte("lorem ipsum dolor sit amet")
		enc, e := packer.Pack(pld, senderKey, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		var validJwe *Envelope
		e = json.Unmarshal(enc, &validJwe)
		require.NoError(t, e)

		// make a jwe copy to test with scrambling its values
		jwe := &Envelope{}
		deepCopy(jwe, validJwe)

		// create a new packer for rec1 for testing decryption
		packer, e = New(recipient1KMSProvider, XC20P)

		// test bad jwe format
		enc = []byte("{badJWE}")

		// update jwe with bad cipherText format
		jwe.CipherText = "badCipherText"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce format
		dec, e := packer.Unpack(enc)
		require.EqualError(t, e, "unpack: illegal base64 data at input byte 12")
		require.Empty(t, dec)
		jwe.CipherText = validJwe.CipherText

		// update jwe with bad nonce format
		jwe.IV = "badIV!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce format
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: illegal base64 data at input byte 5")
		require.Empty(t, dec)
		jwe.IV = validJwe.IV

		// update jwe with bad tag format
		jwe.Tag = "badTag!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag format
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Tag = validJwe.Tag

		// update jwe with bad recipient spk (JWE format)
		jwe.Recipients[0].Header.SPK = "badSPK!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: sender key: bad SPK format")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.SPK = validJwe.Recipients[0].Header.SPK

		// update jwe with bad recipient tag format
		jwe.Recipients[0].Header.Tag = "badTag!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.Tag = validJwe.Recipients[0].Header.Tag

		// update jwe with bad recipient nonce format
		jwe.Recipients[0].Header.IV = "badIV!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: illegal base64 data at input byte 5")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.IV = validJwe.Recipients[0].Header.IV

		// update jwe with bad recipient nonce format
		jwe.Recipients[0].Header.IV = "badNonce"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: bad nonce size")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.IV = validJwe.Recipients[0].Header.IV

		// update jwe with bad recipient apu format
		jwe.Recipients[0].Header.APU = "badAPU!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: illegal base64 data at input byte 6")
		require.Empty(t, dec)
		jwe.Recipients[0].Header.APU = validJwe.Recipients[0].Header.APU

		// update jwe with bad recipient kid (sender) format
		jwe.Recipients[0].Header.KID = "badKID!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, fmt.Sprintf("unpack: %s", cryptoutil.ErrKeyNotFound.Error()))
		require.Empty(t, dec)
		jwe.Recipients[0].Header.KID = validJwe.Recipients[0].Header.KID

		// update jwe with bad recipient CEK (encrypted key) format
		jwe.Recipients[0].EncryptedKey = "badEncryptedKey!"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: illegal base64 data at input byte 15")
		require.Empty(t, dec)
		jwe.Recipients[0].EncryptedKey = validJwe.Recipients[0].EncryptedKey

		// update jwe with bad recipient CEK (encrypted key) value
		jwe.Recipients[0].EncryptedKey = "Np2ZIsTdsM190yv_v3FkfjVshGqAUvH4KfWOnQE8wl4"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: chacha20poly1305: message authentication failed")
		require.Empty(t, dec)
		jwe.Recipients[0].EncryptedKey = validJwe.Recipients[0].EncryptedKey

		// now try bad nonce size
		jwe.IV = "ouaN1Qm8cUzNr1IC"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad nonce value
		require.PanicsWithValue(t, "chacha20poly1305: bad nonce length passed to Open", func() {
			dec, e = packer.Unpack(enc)
		})
		require.Empty(t, dec)
		jwe.IV = validJwe.IV

		// now try bad nonce value
		jwe.Recipients[0].Header.IV = "dZY1WrG0IeIOfLJG8FMLkf3BUqUCe0xI"
		enc, e = json.Marshal(jwe)
		require.NoError(t, e)
		// decrypt with bad tag
		dec, e = packer.Unpack(enc)
		require.EqualError(t, e, "unpack: decrypt shared key: chacha20poly1305: message authentication failed")
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
				SPK: r.Header.SPK,
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
	var recipientPrivStr = "c8CSJr_27PN9xWCpzXNmepRndD6neQcnO9DS0YWjhNs"
	recipientPriv, err := base64.RawURLEncoding.DecodeString(recipientPrivStr)
	require.NoError(t, err)

	var recipientPubStr = "AAjrHjiFLw6kf6CZ5zqH1ooG3y2aQhuqxmUvqJnIvDI"
	recipientPub, err := base64.RawURLEncoding.DecodeString(recipientPubStr)
	require.NoError(t, err)

	// mocking signature keys as enc keys
	_, refKS := mockkms.CreateKeys(recipientPub, recipientPriv, recipientPub, recipientPriv)

	// create mockkms provider with the above keys
	mockKMSProvider, err := mockkms.NewMockProvider(refKS)
	require.NoError(t, err)

	// refJWE created by executing PHP test code at:
	// https://github.com/gamringer/php-authcrypt/blob/master/examples/1-crypt.php
	//nolint:lll
	const refJWE = `{
    "protected": "eyJ0eXAiOiJwcnMuaHlwZXJsZWRnZXIuYXJpZXMtYXV0aC1tZXNzYWdlIiwiYWxnIjoiRUNESC1TUytYQzIwUEtXIiwiZW5jIjoiWEMyMFAifQ",
    "recipients": [
        {
            "encrypted_key": "46R0uW5KUbaZYt5PpIW5j1v_H8BS2SLrdPEzUaK8V0U",
            "header": {
                "apu": "tDzm-bgMblZUgzONI7NTHcSqObP9NX21Vkeid8RFf-PzbJrdU3ApC_f0fDfZVxTwyw-5OZQcTti1H1esIfBFvg",
                "iv": "5HTxplQx5sOfwWtfR5oK416ahbRChh-b",
                "tag": "qrtr29m4EKh5WV6l47fcCw",
                "kid": "18tUZoFCoRVEHdxTyNLRxzcKYV7ZyBm98gunvcChKr1",
                "spk": "eyJ0eXAiOiJqb3NlIiwiY3R5IjoiandrK2pzb24iLCJhbGciOiJFQ0RILUVTK1hDMjBQS1ciLCJlbmMiOiJYQzIwUCIsImVwayI6eyJrdHkiOiJPS1AiLCJjcnYiOiJYMjU1MTkiLCJ4IjoiT0ZkRlN3bTR5Sm5oZmxZNUNZZ1FSVG9ra2ExNHQ0VnNCM216M0N4XzZuayJ9LCJpdiI6Ik5SZkp6Z1N5UE9JU3dOMURSR3lTSERXcXVqdUVXQmgtIiwidGFnIjoibTFsekRSTTl5VEp5cEJOYkVnSE5adyJ9.KIcpv4hUlq0gAb8FpWkSWFnlcshrdNRz51iVoTFyy7E.53YTian9wG5u-S2J2YTjI1TayqW-YMuL.uw6ucr25OIZTfsGQRp8t9fllV0ClBmuhblnTHG6hlh0EEqAWal9jgd6jDbf6Xb_HPzpLSfX7uwYTA11Ui7jZloP8aRjnAKsiEO1-4d-R.GTwXUgcy89zjIAi1Z4WpIA"
            }
        }
    ],
    "aad": "rC0KS-IDOnn39WJvPXJQmP3M5qd_Ax4sYidWXdXSIek",
    "iv": "JS2FxjEKdndnt-J7QX5pEnVwyBTu0_3d",
    "tag": "2FqZMMQuNPYfL0JsSkj8LQ",
    "ciphertext": "qQyzvajdvCDJbwxM"
}`

	packer, err := New(mockKMSProvider, XC20P)
	require.NoError(t, err)
	require.NotNil(t, packer)

	dec, err := packer.Unpack([]byte(refJWE))
	require.NoError(t, err)
	require.NotEmpty(t, dec)
}
