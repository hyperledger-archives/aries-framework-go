/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	insecurerand "math/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/nacl/sign"
)

// failReader wraps a Reader, used for testing different failure checks for encryption tests.
//	count: count the number of Reads called before the failWriter fails.
type failReader struct {
	count int
	data  io.Reader
}

// newFailReader constructs a failWriter
func newFailReader(numSuccesses int, reader io.Reader) *failReader {
	fw := failReader{numSuccesses, reader}
	return &fw
}

// Write will count down a counter, with each call, and fail when the counter is 0
// It calls the wrapped Writer until it's time to fail, after which all calls fail.
// Note: the wrapped Writer can still return errors.
func (fw *failReader) Read(out []byte) (int, error) {
	if fw.count <= 0 {
		// panic(fw)
		return 0, errors.New("mock Reader has failed intentionally")
	}
	fw.count--
	return fw.data.Read(out)
}

func TestBadConfig(t *testing.T) {
	t.Run("Missing recipients", func(t *testing.T) {
		senderKey, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)

		_, err = New(*senderKey, []*publicEd25519{})
		require.Errorf(t, err, "empty recipients keys, must have at least one recipient")
	})

	t.Run("Bad sender keyPair", func(t *testing.T) {
		senderKey := keyPairEd25519{}

		recKey, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)

		_, err = New(senderKey, []*publicEd25519{recKey.pub})
		require.Errorf(t, err,
			"sender keyPair not supported, it must have a %d byte private key and %d byte public key",
			ed25519.PublicKeySize, ed25519.PrivateKeySize)
	})
}

func TestEncrypt(t *testing.T) {
	t.Run("Success test case: given keys, generate envelope", func(t *testing.T) {
		senderKey := getB58EdKey(
			"Bxp2KpXeh6RgXXRVGRQUskT9qT35aSSz1JvdbMUcB2Yc",
			"2QqgiHtrUtDPpfoZG2C3Qi8a1MbLQuTZaaScu5LzQbUCkw5YnXngKLMJ8VuPgoN3Piqt1PBUACVd6uQRmtayZp2x")

		print("sendPK: ", base58.Encode(senderKey.pub[:]), "\n")
		print("sendSK: ", base58.Encode(senderKey.priv[:]), "\n")

		recipientKey := getB58EdKey(
			"9ZeipG91uMRDkMbqgkJK2Fq59CoWwfeJx2e5Q543mU5Q",
			"23Y2dbcT78KEV1T7niUAuf83J8Zta11FG88n6y6pWgZY35nWrhyxGcqCJV5ddHveRZecrhwku77ik7gPSLaXnJXt")

		crypter, e := New(*senderKey, []*publicEd25519{recipientKey.pub})
		require.NoError(t, e)
		require.NotEmpty(t, crypter)
		enc, e := crypter.Encrypt([]byte("Pack my box with five dozen liquor jugs!"))
		require.NoError(t, e)
		require.NotEmpty(t, enc)

		printPythonData(recipientKey.pub[:], recipientKey.priv[:], enc)
	})

	t.Run("Generate keys, generate envelope", func(t *testing.T) {
		senderKey, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)
		recipientKey, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)

		crypter, err := New(*senderKey, []*publicEd25519{recipientKey.pub})
		require.NoError(t, err)
		require.NotEmpty(t, crypter)
		enc, err := crypter.Encrypt([]byte("A very bad quack might jinx zippy fowls."))
		require.NoError(t, err)
		require.NotEmpty(t, enc)

		printPythonData(recipientKey.pub[:], recipientKey.priv[:], enc)
	})

	t.Run("Generate testcase with multiple recipients", func(t *testing.T) {
		senderKey, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)
		rec1Key, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)
		rec2Key, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)
		rec3Key, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)
		rec4Key, err := randEdKeyPair(rand.Reader)
		require.NoError(t, err)

		recipientKeys := []*publicEd25519{
			rec1Key.pub,
			rec2Key.pub,
			rec3Key.pub,
			rec4Key.pub,
		}

		crypter, err := New(*senderKey, recipientKeys)
		require.NoError(t, err)
		require.NotEmpty(t, crypter)
		enc, err := crypter.Encrypt([]byte("God! a red nugget! A fat egg under a dog!"))
		require.NoError(t, err)
		require.NotEmpty(t, enc)

		printPythonData(rec3Key.pub[:], rec3Key.priv[:], enc)
	})

	t.Run("Encrypt empty payload using deterministic random source, verify result", func(t *testing.T) {
		senderKey := getB58EdKey("4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9",
			"5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ")

		recipientKey := getB58EdKey("CP1eVoFxCguQe1ttDbS3L35ZiJckZ8PZykX1SCDNgEYZ",
			"5aFcdEMws6ZUL7tWYrJ6DsZvY2GHZYui1jLcYquGr8uHfmyHCs96QU3nRUarH1gVYnMU2i4uUPV5STh2mX7EHpNu")

		source := insecurerand.NewSource(5937493) // just a random const
		constRand := insecurerand.New(source)

		crypter, err := New(*senderKey, []*publicEd25519{recipientKey.pub})
		require.NoError(t, err)
		crypter.setRandSource(constRand)
		require.NotEmpty(t, crypter)
		enc, err := crypter.Encrypt(nil)
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRWFYwYUdOeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklqSmlVRFl0VnpaWldXZHpjMlZpVWxOaU0xWlljV0pMTlZWa2FpMDNOSGxGTTFFdFZXaHpjMUF3Vm1aclRHNVhiMFk0WjBSNVVHRkJlREI0VWtGM2NIVWlMQ0pvWldGa1pYSWlPbnNpYTJsa0lqb2lRMUF4WlZadlJuaERaM1ZSWlRGMGRFUmlVek5NTXpWYWFVcGphMW80VUZwNWExZ3hVME5FVG1kRldWb2lMQ0p6Wlc1a1pYSWlPaUpHYzIwMU5WOUNTRkJzVkdsd2RUQlFabEZDY2t0SmRuZ3lTRGw0VTBndFVtbHpXRzgxVVdoemQwTTNjR28yTm5BMVNtOUpVVjlIT1hGdFRrVldNRzVGVG5sTVIwczFlVVZuUzJoeU5ESTBVMnBJYkRWSmQzQnljRnBqYUdGNVprNWtWa2xJTFdKNlprRnhjbXhDWTIxUVZEWkpkR2R4Y3poclRHczlJaXdpYVhZaU9pSm1OV3BVT0VKS2FHeEVZbTQwUWxvMFNGcGZSSEExTkU5TGQyWmxRV1JSTWlKOWZWMTkiLCJpdiI6ImlLZHFxRWpzTktpeW4taGsiLCJ0YWciOiIySm5SbF9iXzM2QS1WaWFKNzNCb1FBPT0ifQ==" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Encrypt payload using deterministic random source for multiple recipients, verify result", func(t *testing.T) {
		sender := getB58EdKey("9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw",
			"2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR")
		rec1 := getB58EdKey("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs",
			"33SjJwDk7vKL4tEyVT45XwzebdAVEpRqXJHRrT228pet7hhTFCSdFgnhvrSPX6PfsELM94Wrwwp6JdaFBFReZTBB")
		rec2 := getB58EdKey("G79vtfWgtBG5J7R2QaBQpZfPUQaAab1QJWedWH7q3VK1",
			"3JVueJUSpj68N2HnRwzywiupgVhqeZBpQSztBD8YEtUqDUmWdrAd6K51dZyuoSTNTPCmPEDgkikuFGwWuh63dz8T")
		rec3 := getB58EdKey("7snUUwA23DVBmafz9ibmBgwFFCUwzgTzmvcJGepuzjmK",
			"3VaBzg9FgCq87etzLXktPWRFDJyUJrkxU9v5SwXVJE2WFMuaeffAjr3QTWWwjf3U8byJCwusZQqeuBZgAZphH16y")
		rec4 := getB58EdKey("GSRovbnQy8HRjVjvzGbbfN387EX9NFfLj89C1ScXYfrF",
			"jM6QdBopsuAz95PdFwwSg3ARSVQohArPKaZWNcvgLBz5NkqkZNCMMjftsXjHbGk7QLq7nabBV5FdHPnmXdhhdCB")

		source := insecurerand.NewSource(6572692) // just a random const
		constRand := insecurerand.New(source)

		crypter, err := New(*sender, []*publicEd25519{rec1.pub, rec2.pub, rec3.pub, rec4.pub})
		require.NoError(t, err)
		crypter.setRandSource(constRand)
		require.NotEmpty(t, crypter)
		enc, err := crypter.Encrypt([]byte("Sphinx of black quartz, judge my vow!"))
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRWFYwYUdOeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNkltRlliRkl0Umkwd2JEZFZTMU10Vkhwb1MwaGFWMmhIWlMxUU5tbzRlVUYwU2pFeFVEbHlSMU4yVFZGQmNHVnpZbk5wTUVsRE5XVmlVREJoVW5kVFozVWlMQ0pvWldGa1pYSWlPbnNpYTJsa0lqb2lSRVJyTkdGak1scEJNVGxRT0hGWWFtczRXR0ZEV1RsR2VEZFhkMEZ0UTNSRlRHdDRaVVJPY1ZNMlZuTWlMQ0p6Wlc1a1pYSWlPaUk1ZG1oRVdHMXBMWFJVVDBaS1FuRTRXSGhSZUROVmFUVk1SemxIT0ZoRlUxTTBaVjlST0ZCNVFUQlhhR0pCZHkxR2FscFpNVzlRWjJSb1YwOWhPVWRCTlVFd1puSkVVMHBzWm5Nd2VVNDRNVmsxV0V0a1MyUlZOVkJoTlRGdlRuQmFOVlV4VmtKSGQycG1WMmxhU0hOc05DMHhOamhuVG01cGVFazlJaXdpYVhZaU9pSjBUMjlFTW1RMVZrdFdRV2xITlMxNGNqWnFNM1UzTkZWalZUWlVibTlVWHlKOWZTeDdJbVZ1WTNKNWNIUmxaRjlyWlhraU9pSmZZa3RtVUdjM056WnphRmR5TXpWMmVXWm1jV05NZW1oTE1VUlJRV0owWTFaQ1pFVXlNM1ZUVEVGUmRHSkdNVUZMYkRrMmJHcE5WSHBzTmt4d2JuYzBJaXdpYUdWaFpHVnlJanA3SW10cFpDSTZJa2MzT1haMFpsZG5kRUpITlVvM1VqSlJZVUpSY0ZwbVVGVlJZVUZoWWpGUlNsZGxaRmRJTjNFelZrc3hJaXdpYzJWdVpHVnlJam9pVUVWNlZrc3laM1JJU25OcWFuSjVNbEZ3ZG0xYVFXazRSSGRUT1ZrM2RuVkZkakJ3Wm1JdFgyc3pRbmxQUjJoSGRHUmxUMlJUVjJaaVZrazFXRVJuV0UxNFVVWjNNM1prWHpoa2RtUndSMFZDWlZsVlNFbHBRMEZuT0VaNlZqSkNZVkZyWDFCSGRDMUliMjFJVFZoNVp6VTBUbHBCVWtsS2RXNVZQU0lzSW1sMklqb2lVV1ZRU0RRM2FsTkxXVU14Y2pSb1h6QldjMlJJVlRSWU1FZENkME5ZVWtVaWZYMHNleUpsYm1OeWVYQjBaV1JmYTJWNUlqb2lTMVZDU3pWRFIwMU5SR1ZDVkV4dFYwSmZObWQxWVhCSGNWWlZaRUpQTWxFdFkyTkdaVXRHZEZjMWRqZEpUbmhWY1VKa1FWcExlRkpGZWxFMlNEQnpXaUlzSW1obFlXUmxjaUk2ZXlKcmFXUWlPaUkzYzI1VlZYZEJNak5FVmtKdFlXWjZPV2xpYlVKbmQwWkdRMVYzZW1kVWVtMTJZMHBIWlhCMWVtcHRTeUlzSW5ObGJtUmxjaUk2SW1NdFZHRnlTSGgyVW5WTlgybFBTRnBFWkZkbVkwbG1jSGhtYVV3eVdXVlRObk4yYUZKRFRuZGlkMUpxWXpBdFJFZFllbVpTU0RkSVNEaDBOa0ZpYm5SbE1FeG5ZbGd4VGpjelQyMVJUM1ZHVUVkWlQxbFdiRGw2YTFCSlprdzNMWGh4YmtKRVF6Tm5MVkpFU0ZoNlgxSkpSSEp3WWpOVU1VTk9UVDBpTENKcGRpSTZJbGgwYVc5SFUyOWxOR0ZWV1Rac2JYcHNOVkIxWlRkMU9FOWxSMWN4YkVNNEluMTlMSHNpWlc1amNubHdkR1ZrWDJ0bGVTSTZJbEV5Wld4YVQyRktiWFZCYjA5S05GRjJXWE52YVc5R1RsRm9ha2w0UjJSWFZuZHpkV2R3WW05Q1ZucHViVVJHTjB4RFZ6RjNjMUZoTUVwMVpreHFkMjhpTENKb1pXRmtaWElpT25zaWEybGtJam9pUjFOU2IzWmlibEY1T0VoU2FsWnFkbnBIWW1KbVRqTTROMFZZT1U1R1preHFPRGxETVZOaldGbG1ja1lpTENKelpXNWtaWElpT2lKc1NYcGxNR0p3UzJ4cWNuVlRMWGREV21wUWVuWmZRMDAwUW1SdmMweHpNbDlKTUZZeFUxQnZla05uWDA5emNVRTViVEZCUVhoWmVVMXZhVXhvVkUxdU9ERmtPREo2YUd4WmVXVmxVMWxTZVdaSmNUZGFYMTlrTVRNemExcE9Wa054UVdwWFEyRllURmxxVjNoamVIUlNjRFJTYkVwYVlrOUxRVVU5SWl3aWFYWWlPaUpvTUdWTGJtRkZOVXhoWDJKYVpHVkNVR0Z1Vm0wNFpGZFVlRkZEU2xGQ2VpSjlmVjE5IiwiaXYiOiJZb3VDVi1nbGZRaFBhbDc1IiwiY2lwaGVydGV4dCI6Il9jRUNrMDQ3Y2w4Y3dFaUs1UnZLbHZORDJjTlo1bTZBTW9vdlI4MnBpMEhLbzFnZlZBPT0iLCJ0YWciOiJCYWZ4TW1CU2R5bmI0dmxvQ3ptUVNRPT0ifQ==" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})
}

func TestEncryptComponents(t *testing.T) {
	sender := getB58EdKey("9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw",
		"2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR")
	rec1 := getB58EdKey("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs",
		"33SjJwDk7vKL4tEyVT45XwzebdAVEpRqXJHRrT228pet7hhTFCSdFgnhvrSPX6PfsELM94Wrwwp6JdaFBFReZTBB")

	crypter, err := New(*sender, []*publicEd25519{rec1.pub})
	require.NoError(t, err)

	t.Run("Encrypt fail: content encryption nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(0, rand.Reader)
		crypter.setRandSource(failRand)

		_, err = crypter.Encrypt([]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"))
		require.Errorf(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Encrypt fail: CEK generation fails", func(t *testing.T) {
		failRand := newFailReader(1, rand.Reader)
		crypter.setRandSource(failRand)

		_, err = crypter.Encrypt([]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"))
		require.Errorf(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Encrypt fail: recipient nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(2, rand.Reader)
		crypter.setRandSource(failRand)

		_, err = crypter.Encrypt([]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"))
		require.Errorf(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Encrypt fail: recipient sodiumBoxSeal nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(3, rand.Reader)
		crypter.setRandSource(failRand)

		_, err = crypter.Encrypt([]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"))
		require.Errorf(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Encrypt success: 4 reads necessary for encrypt", func(t *testing.T) {
		failRand := newFailReader(4, rand.Reader)
		crypter.setRandSource(failRand)

		_, err = crypter.Encrypt([]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"))
		require.NoError(t, err)
	})

	t.Run("Failure: generate recipient header with bad sender key", func(t *testing.T) {
		crypter2, e := New(*sender, []*publicEd25519{rec1.pub})
		require.NoError(t, e)

		badSender := keyPairEd25519{}
		crypter2.sender = badSender

		_, e = crypter2.buildRecipient(nil, nil)
		require.Errorf(t, e, "key is nil")
	})

	t.Run("Failure: generate recipient header with bad recipient key", func(t *testing.T) {
		crypter2, e := New(*sender, []*publicEd25519{rec1.pub})
		require.NoError(t, e)

		_, err = crypter2.buildRecipient(nil, nil)
		require.Errorf(t, err, "key is nil")
	})
}

func TestDecrypt(t *testing.T) {
	t.Run("Fail, Decrypt not implemented", func(t *testing.T) {
		sender := getB58EdKey("9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw",
			"2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR")
		rec1 := getB58EdKey("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs",
			"33SjJwDk7vKL4tEyVT45XwzebdAVEpRqXJHRrT228pet7hhTFCSdFgnhvrSPX6PfsELM94Wrwwp6JdaFBFReZTBB")

		crypter, err := New(*sender, []*publicEd25519{rec1.pub})
		require.NoError(t, err)

		_, err = crypter.Decrypt([]byte{}, rec1.priv)
		require.Errorf(t, err, "not implemented")
	})
}

func TestSodiumBoxSeal(t *testing.T) {
	var err error

	recipient1Key, err := randCurveKeyPair(rand.Reader)
	require.NoError(t, err)

	t.Run("Generate a box_seal message to compare to ACA-Py:", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := sodiumBoxSeal(msg, recipient1Key.pub, rand.Reader)
		require.NoError(t, err)

		// Python implementation expects the nacl 64-byte key format
		t.Logf("recipient VK: %s", base64.URLEncoding.EncodeToString(recipient1Key.pub[:]))
		t.Logf("recipient SK: %s", base64.URLEncoding.EncodeToString(recipient1Key.priv[:]))
		t.Logf("sodiumBoxSeal() -> %s", base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Seal a message with sodiumBoxSeal and unseal it with sodiumBoxSealOpen", func(t *testing.T) {
		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := sodiumBoxSeal(msg, recipient1Key.pub, rand.Reader)
		require.NoError(t, err)
		dec, err := sodiumBoxSealOpen(enc, recipient1Key.pub, recipient1Key.priv)
		require.NoError(t, err)

		require.Equal(t, msg, dec)
	})

	t.Run("Seal message, present signing key", func(t *testing.T) {
		rec := getB58CurveKey(
			"DJuB84EKcHjMcwRKV2CP6pDSWG8xL8V2yntcLpvuHTj4",
			"9foNvM6BPbcAohay8cEkDG6BZj26Tave6k1mGcPx63yW")

		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := sodiumBoxSeal(msg, rec.pub, rand.Reader)
		require.NoError(t, err)

		// Python implementation expects the nacl 64-byte key format
		t.Logf("sodiumBoxSeal() -> %s", base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Failed decrypt, short message", func(t *testing.T) {
		enc := []byte("Bad message")

		_, err := sodiumBoxSealOpen(enc, recipient1Key.pub, recipient1Key.priv)
		require.Errorf(t, err, "message too short")
	})

	t.Run("Failed decrypt, garbled message", func(t *testing.T) {
		rec := getB58CurveKey(
			"DJuB84EKcHjMcwRKV2CP6pDSWG8xL8V2yntcLpvuHTj4",
			"9foNvM6BPbcAohay8cEkDG6BZj26Tave6k1mGcPx63yW")

		msg := []byte("lorem ipsum dolor sit amet consectetur adipiscing elit ")

		enc, err := sodiumBoxSeal(msg, rec.pub, rand.Reader)
		require.NoError(t, err)

		enc[0]++ // garbling

		_, err = sodiumBoxSealOpen(enc, rec.pub, rec.priv)
		require.Errorf(t, err, "failed to unpack")
	})
}

func TestNonceGeneration(t *testing.T) {
	t.Run("Verify nonce against libsodium generated data", func(t *testing.T) {
		data := [][]string{
			{"6Gy2UWZCvYcTnpNvQX6ZNhz8FEofrhVxLCEPrjNTTZui", "9mGybrrDfGPdnGXA4BXbzJXnbg2w27bZ1ok6whbJrhF9",
				"EWqT43jjhcy4wJHamH2RFthdLAQhits8F"},
			{"GJBA64X9GReJrUttG4xQ1dLm726Sn3XQE5hAQeiCZtBV", "kRU8Ef7NTmhijeqKyWzZaZmVAq5UhnpfMfzsBYgBGrV",
				"Kr7Wi5EGyTVNQy44oeFcBJtJJ7dVvXEAL"},
			{"CYx2Jtgti3Rc45ZCgHMWxSCVYgivwcy2PKcXDpadJz5M", "2gWhujzcfRtpeZhiXeXoARqzCzBESdKUG5DoAzLCzhSY",
				"MZ53sJMYDDtA9JUTFSqmXmD7s7m6hVW2m"},
			{"At8qPKFRTPzTBjvEUxWzQ3Sc7B3Ywk5G2tEmrzcMWo8C", "2GBiu2FEtSpxDJ4C8bdCUfTfsqW8eb39M985uB85NbC8",
				"6UU5xChzZFsBHgzFMDga8jnLwSqcS46Ln"},
			{"7rRY74rDVcjghFP9y8fR15xxmZaHBuZnFrYTXwnmwrnE", "CCs3kZHuXSM7mcH5yrXp5bCzMqDsBztqcHsRvgmJBN7D",
				"MPEnkeoVe8X67yBK9k2AZdXHw4e2udx2X"},
		}

		for _, datum := range data {
			pub1 := base58.Decode(datum[0])
			pub2 := base58.Decode(datum[1])

			correctNonce := base58.Decode(datum[2])
			testNonce, err := makeNonce(pub1, pub2)

			require.NoError(t, err)
			require.ElementsMatch(t, correctNonce, testNonce)
		}
	})
}

func TestKeyConversion(t *testing.T) {
	t.Run("Test public key conversion", func(t *testing.T) {
		// Test data generated using GoKillers/libsodium
		edPubs := []string{
			"GV28sQUKYSWdkYtu7h46ACGvjbpL7BUv8TZJr5Lukxra",
			"6a58vqYauxsAU2J1dGXNxTDcC6nPyntxM2bh8YWJBwTW",
			"9UKEhZgwcpbvrfxAyy7hzFzYJvtf48EvmjAfcFUZYLNk",
			"5aa4euy5AGiS9JqDeCTgWqUmFmd64ADKergicwoG2jFU",
			"BF3niopmPgYV6xRmTJMMR88ZMnHeJXoCYiQ4Q9qCMpHU",
			"AdHgkKSDMD3YLYzua8yczqFTeLgYdD6W3LR5wjogEUk9",
			"EFnybhqg65JqfankLNKeQb228dkNcVF1c7vzdtvNaz6J",
			"2HbU7ZiZ398b4SvU6b9GVGE4W3UEjYcTStgvNpPb2oUc",
			"2r4M2aL4YDE2Qy6MzLWb3it93Mt84oSGrPNJ9V6VaAF4",
			"CTsYpNjdhK68mjkE4wNrnTVW2qERFNoPXWBnUW9E9bhz",
			"B7PGAJGqfei7cKFvaaF53uPDVmWBkVyLe5UqmrL3GVmF",
			"CJZRRZyhpz29qf8uBfmUWrHa8G3XwEmtYdwiNyT42XeK",
			"3q99EhPvy4ma62BGztcyabGHtX7sZjBtnfkJyE7JJmF8",
			"8HTpnbCjbFxX8Nwx131eHwJU7dsVaupuPKDtsaeF9phe",
			"89JQa4hvQU3Pk7oY8eBYrZp49ZkpVaZWLHSsxjmq9W1b",
			"EVQM6epVv9ZGkAnPJBX7ns8zS3Nf5EKd9iSpbv5aqCRn",
			"CiNPtf1mfdkEYRGCXiCurCNMjydZjuedbPG9kVgy4UyN",
			"DKS6yB7oGMExmAFKiEAYufDevQuAHCq9UtaKJFmSzJ3k",
			"8UwSjbTo3FwMC4CxqqLJBWik67ubBtE8RRC7FvxjA7xU",
			"Ati3h5YVzWUjdrT956dqYh5NXZaDYqRXoHpp5Htcjxoj",
		}

		curvePubs := []string{
			"8sKzfbhmTnCURJYwTsBvNbXyjNMzKy7kyZNMJe8PspLD",
			"BMKZw7RcyieQHihYMvSGVZ8UFogHjoorWndJnz9L25Hm",
			"D8X75d5pGTiHFYR7m2iqMjQehjd3v8MFejAGP2Mcirzu",
			"3JMxHyQEwnrHhKgemRvCtjp3Z2T9UGVTMXfBKWpNQe3B",
			"3gYHgo7UKQg2CV7RT67yYSRkN7X5UZhL8CTJZefU5i5x",
			"BA1dA5CZuSWPjyGsW94mT2kgUVRBUppiGPkd4M2RdD69",
			"7S8cYe1gd1jWy4DUp3nBVW5TmYXKnGcTMLk3xnhiEp1b",
			"G215pJNTMDWafrDGHenjbAkpWoM3w9dfY5tAbWEx8pyR",
			"37rPhyJfRcZk6v3Lq9kmZJMBUjyvfroniBXMiZdh7PVq",
			"5FmcvFtPrdxD5GJc5P9SpVzvhSNyJDdQGPnrLnzCV64z",
			"73GaEVd6oXEgqPKYmvbFg2jccMG5VLmq65Bn7gS56BRQ",
			"A6W67iKzaohB4LDNa4XsAaHQbbgzdLtmaNPq6TfciRaS",
			"AuANoekPVzVrNn3dbkmvMhRA926Z4rtH96jnksJ26MyK",
			"FD3XcmwNmoZQ1bKfLDyk151kqsh7xVXH5W7GHt9ZJRLJ",
			"5CpahvkR9BTzCtry63UeXgdWJBFdNBXd42trefE6K4jf",
			"3u8zsCK3uipjMrXjpXTWj9me74wLR45YxvN7qmE3aRFb",
			"5u3af9JJQQGSo42wgzeBBfhctoPUYTRXUGCMU64DpqpH",
			"6b2Hc6mxnZTBW9fkNEiDyGNKnt7XuQcbDVzMGoqJfR5Y",
			"DScPyc8TY6pEYWFZxQyhUvUoZEHbEJKxeE23wUS9A6hj",
			"CWY4n7zi6KysyvsVHXtBAW9cQ9esFerxLZfTedfom3mF",
		}

		for i, edKeyString := range edPubs {
			edKeyBytes := base58.Decode(edKeyString)
			edKey := publicEd25519{}
			copy(edKey[:], edKeyBytes)

			curveKeyBytes := base58.Decode(curvePubs[i])
			curveKey := publicCurve25519{}
			copy(curveKey[:], curveKeyBytes)

			convert, err := publicEd25519toCurve25519(&edKey)
			require.NoError(t, err)
			require.ElementsMatch(t, curveKey, convert[:])
		}
	})

	t.Run("Test private key conversion", func(t *testing.T) {
		// Test data generated using GoKillers/libsodium
		edPrivs := []string{
			"DH43p5VzoVzDkgkQzgzybE9Z2hK8KevuS9x56A6AEKscHBS3ZXaf6hU4kP6VPM421REUoxCssVeif9XCVaGhURS",
			"42LHpaJQCLs1JNANNqvbD5of5MDgsYEtZ4DXRJCouADyc6BGryHSv5BzHvvtFQu21XtMNP3nz5XRWVk2t8BBPS2b",
			"3KsjZqADnZhKy7gb6FmsaWGYAyyawHvoW4RccUfYYTNjG9y1RN8z6FjTQMEhW3rh93Xs4aEGdbbzs9zi63ovzHQm",
			"37uWqrXwpWK19P7EMNw7kXjMucvPSDuJbwjdZrFynebuFJL165w6hH4ergNWVZyB39atHhBjyK1U6WLMPrUL5FB8",
			"2bXak57U5YKF8j2Ked6JoTPJr1SBs7Fap99vL5EjPS69fqsE1gSmG1KLY3tE58CWaRRDf422dtTaJjpYw1tc3xoj",
			"4kR1WSRU3jzDU4EZgZGaf22a9SkoQcWWdYLRAyVDXMBhDGNc4wnREVtKb4rzZ9q6jP7ANCcsqVS7C4DkQ6AKkbAH",
			"3PRatPTTQ5d7Dj5eaLaRvnbE5J28M5s1PSaZ2THmZuvXRo9Piq6dnuXcdxr39ezceCHoHmGRpPwBfKK8dWb7BVi9",
			"5WTFGmXkxJc2p9XTXMwjrqCkTn1SJMCBAGQ3yDKEm9TVQF3nWwLWRneFrXzDzgBYcUo1Mxj3Ym46BYgqQWgLGSTW",
			"2x4qYudE5J2rA9JQFHTHevn4nYaVJtT3f7RCzqWjZ3726tCUHbgzg74QBSzhGbWVpfQhtaRZ8RsMkcnMjGqNzrj5",
			"2QAb1BPVidRV9dxb1BsZ137vXP1fQb2BbCBWo5fb5Tpj8vV1fU2vVake8JSiMBmU8XfcR8yxDmBezzbGQCKeEUds",
			"5e5yq8BzzZ9MYJxkrFX4DDR6RxvwiFP1TqtimpjeQdRF16Cfq1aqVEnKbh6eRAJd7PZXuq9hMYtwLyqCeMSaaTT4",
			"2tHVLALEobsefPsLprDJb7FPZ5Cj9F6zMU6hiVp9LSu2XP5AqCXxvKB18uwo4PHK8DNaAdkQ78diMtb5NBw3p9km",
			"5YCxw8E9kkt46DKRv5SkJ28ZH3DoMJhSHxpPoRQhPNaP3Ve4pJyaBoKotFvpLwuwi2MwjfDMZbkfBFvQKqudrp8Q",
			"277X3QJjmJVXgULzUJ87bYg76tTfnVbufhRCBJJNqBUP1hqPqueXLCKNfDrdp5atdKp18tLkSKT54yt4ef7ZL393",
			"4k7nC7YKkhmTArmKYXBqQWYXAX4wzhNkaWT5RUTbczaj54iAXdUvcoXUjBgK5J5cWbLp7q55sCnv3SwNSKBbPraP",
			"KKP9gymE9GvMn83LGqth7QuD7Vd4vbzsyLqCYgnnLPJdY8VuzciC4cdCvRpHvmGXXFUxyzNe7V97QBD3AxMXyPY",
			"5oST3U3ffd8iamT7QgadQvyPGh58nr9r4CCiMW45ucV8qupDcmMAUFTLiPCKKYX9tPV69qfe2wQLC9x53tzxBrzd",
			"38LdKpmjmed3AwDbKhCfjopoKTibn1WLVBsrGgnbRaw9mcXqRyoemmQgcnqR2au3DhB9hQFVVdbtqBeRJxyqQgwU",
			"2e3votxseb2bhdKHAx2uzgQWVExkz7eAHLF1KTQYiSpVzv6s9PkSu6nUBa1EqJFoJvPKiE1PxUMPvLm7Wc4mFWQ",
			"2Dt3qPTHyVPE4EpN5c62zTX1DQnJtQgbwXrkAHo6fKJYYgjnEA7Ggqie4ZfCukWG8sTvBLCoWbhQSJtV5PzFqLp9",
		}

		curvePrivs := []string{
			"3im72Q16HHqfgqziCKR7dKkZF59ZHEGxqc5nfhFqF223",
			"5sa8TDuj2Ha41Khou9yQ8kAVz6bxjwW1idv5QCbWMEcT",
			"6yCAYLdEcyVadtqCbG3ffMx2PqhE1gXfH3enPMwjbLYD",
			"HB3tAasj3hJQVa12EN9a4Ph7GrRyNPDQH1qMKBgZ8s2s",
			"ZyB9Vd461HHHBKzbXFERBMeauPN7smc8MvBRxjvBLyR",
			"9eSnTQusUh1aYdVhfzHUy1F4QLyHh4UpM3yV37vqoE4J",
			"9fhmCLQhwFSffe7J7iD8QUBtJ15szDGnaynD9A91EAby",
			"5KNPvL9JF7fpAEuuvGYRPRFa1KG68MFU5EWyW4wN5twb",
			"81SrqWepV72qmWrCDtyay6y2bb9SLXYDat7oCYBAb5s8",
			"G5besqGYbhA78K5hjV7umf1PyyhXV8HJhUhk6PypeWZw",
			"84QJE1CBi4h8xBhQMqwFwUuCYGLXFB31NBirfD3ENduJ",
			"3ic7MKSCj6YnfsGXwr2VACXC3CKhK5HxX81p17mWH4t6",
			"9gF459xtS64bFcDpaCZc5Utqm5SkUUEauKQxekRJZHbs",
			"4qF59e48Hq6nq7tKkJQcUHia2hD3iXVpjX91bW2sp1qs",
			"DSDoiSRmL41WQ4Q8RNWoPfeXSQGn4vwQB4ii9zt7VTpq",
			"BpaTEPTgUMr1XSjVAqMj2j8Q6ZvSEsmbruGfypu9XPDh",
			"Ajds6dh1M1MTetjLHzrYRXYZmepVUoJnTz9Q8VhhDBPg",
			"25ctY6ghvZV5RqTCdZySZVEfE6MLu4jEmFoTURDsQxDT",
			"1akW9fT6rNkbVPCrP4SpLXUhYYrKK69gnjZHnFk6adf",
			"18BWLZh74cem5mKbPZ7nqbBQ8zgqigg1BppVDEhMV3d",
		}

		for i, edKeyString := range edPrivs {
			edKeyBytes := base58.Decode(edKeyString)
			edKey := privateEd25519{}
			copy(edKey[:], edKeyBytes)

			curveKeyBytes := base58.Decode(curvePrivs[i])
			curveKey := privateCurve25519{}
			copy(curveKey[:], curveKeyBytes)

			convert, err := secretEd25519toCurve25519(&edKey)
			require.NoError(t, err)

			require.ElementsMatch(t, curveKey, convert[:])
		}
	})

	t.Run("Fail on converting nil pub key", func(t *testing.T) {
		_, err := publicEd25519toCurve25519(nil)
		require.Errorf(t, err, "key is nil")
	})

	t.Run("Fail on converting nil priv key", func(t *testing.T) {
		_, err := secretEd25519toCurve25519(nil)
		require.Errorf(t, err, "key is nil")
	})

	t.Run("Fail: invalid pubkey, cannot convert to curve25519", func(t *testing.T) {
		edKey := publicEd25519{}
		edKeyBytes := base58.Decode("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7")
		copy(edKey[:], edKeyBytes)

		_, err := publicEd25519toCurve25519(&edKey)
		require.Errorf(t, err, "failed to convert public key")
	})
}

// printPythonData prints the recipient key and message envelope
func printPythonData(recPub, recPriv, envelope []byte) {
	print("## PASTE DATA ##\n")
	print("b58_pub = \"", base58.Encode(recPub), "\"\n")
	print("b58_priv = \"", base58.Encode(recPriv), "\"\n")
	fmt.Printf("msg_in = \"\"\"%s\n\"\"\"\n", envelope)
	print("## END PASTE  ##\n")
}

func randEdKeyPair(randReader io.Reader) (*keyPairEd25519, error) {
	keyPair := keyPairEd25519{}
	pk, sk, err := sign.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	keyPair.pub, keyPair.priv = (*publicEd25519)(pk), (*privateEd25519)(sk)
	return &keyPair, nil
}

func randCurveKeyPair(randReader io.Reader) (*keyPairCurve25519, error) {
	keyPair := keyPairCurve25519{}
	pk, sk, err := box.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	keyPair.pub, keyPair.priv = (*publicCurve25519)(pk), (*privateCurve25519)(sk)
	return &keyPair, nil
}

func getB58EdKey(pub, priv string) *keyPairEd25519 {
	key := keyPairEd25519{new(privateEd25519), new(publicEd25519)}
	pubk := base58.Decode(pub)
	privk := base58.Decode(priv)

	copy(key.pub[:], pubk)
	copy(key.priv[:], privk)

	return &key
}

func getB58CurveKey(pub, priv string) *keyPairCurve25519 {
	key := keyPairCurve25519{new(privateCurve25519), new(publicCurve25519)}
	pubk := base58.Decode(pub)
	privk := base58.Decode(priv)

	copy(key.pub[:], pubk)
	copy(key.priv[:], privk)

	return &key
}
