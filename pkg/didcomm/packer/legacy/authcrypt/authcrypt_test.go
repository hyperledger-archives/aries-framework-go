/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	insecurerand "math/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/internal/mock/kms"
	mockStorage "github.com/hyperledger/aries-framework-go/pkg/internal/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
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

type provider struct {
	storeProvider storage.Provider
	crypto        kms.KeyManager
}

func (p *provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

func (p *provider) InboundTransportEndpoint() string {
	return ""
}

func newKMS(t *testing.T) (*kms.BaseKMS, storage.Store) {
	msp := mockStorage.NewMockStoreProvider()
	p := provider{storeProvider: msp}

	store, err := p.StorageProvider().OpenStore("test-kms")
	require.NoError(t, err)

	ret, err := kms.New(&p)
	require.NoError(t, err)

	return ret, store
}

func persistKeys(pub, priv string, store, metadataStore storage.Store) error {
	sigPub := base58.Decode(pub)
	keyHash := sha256.Sum256([]byte(pub))
	sigPubKey := cryptoutil.Key{
		ID:         base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("sp")...)),
		Value:      pub,
		Capability: cryptoutil.Signature,
		Alg:        cryptoutil.EdDSA,
	}

	sigPriv := base58.Decode(priv)
	sigPrivKey := cryptoutil.Key{
		ID:         base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("ss")...)),
		Value:      priv,
		Capability: cryptoutil.Signature,
		Alg:        cryptoutil.EdDSA,
	}

	sk, err := cryptoutil.SecretEd25519toCurve25519(sigPriv)
	if err != nil {
		return err
	}

	encPrivKey := cryptoutil.Key{
		ID:         base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("es")...)),
		Value:      base58.Encode(sk),
		Capability: cryptoutil.Encryption,
		Alg:        cryptoutil.Curve25519,
	}

	pk, err := cryptoutil.PublicEd25519toCurve25519(sigPub)
	if err != nil {
		return err
	}

	encPubKey := cryptoutil.Key{
		ID:         base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("ep")...)),
		Value:      base58.Encode(pk),
		Capability: cryptoutil.Encryption,
		Alg:        cryptoutil.Curve25519,
	}

	err = storeKey(store, sigPubKey)
	if err != nil {
		return err
	}

	err = storeKey(store, sigPrivKey)
	if err != nil {
		return err
	}

	err = storeKey(store, encPubKey)
	if err != nil {
		return err
	}

	err = storeKey(store, encPrivKey)
	if err != nil {
		return err
	}

	keys := []cryptoutil.Key{
		{ID: sigPubKey.ID},
		{ID: sigPrivKey.ID},
		{ID: encPubKey.ID},
		{ID: encPrivKey.ID},
	}
	h := sha256.Sum256([]byte(pub)) // hashing the base58 public signature key
	// keySet must be stored with ID references only
	keySet := cryptoutil.KeySet{
		ID:   base64.RawURLEncoding.EncodeToString(h[:]),
		Keys: keys,
		PrimaryKey: cryptoutil.Key{
			ID: sigPubKey.ID,
		},
	}

	data, err := json.Marshal(keySet)
	if err != nil {
		return fmt.Errorf("failed to marshal keySet: %w", err)
	}

	err = metadataStore.Put(keySet.ID, data)
	if err != nil {
		return fmt.Errorf("failed to persist main keySet: %w", err)
	}

	// insert a new KeySet referenced by public encryption key for cross reference by encryption key
	keys = []cryptoutil.Key{
		{ID: sigPubKey.ID},
		{ID: encPubKey.ID},
	}
	h = sha256.Sum256([]byte(encPubKey.Value)) // hashing the base58 public encryption key
	keySet.ID = base64.RawURLEncoding.EncodeToString(h[:])
	keySet.Keys = keys

	data, err = json.Marshal(keySet)
	if err != nil {
		return fmt.Errorf("failed to marshal encryption reference keySet: %w", err)
	}

	return metadataStore.Put(keySet.ID, data)
}

func storeKey(store storage.Store, key cryptoutil.Key) error {
	data, err := json.Marshal(key)
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	err = store.Put(key.ID, data)
	if err != nil {
		return err
	}

	return nil
}

func (p *provider) KMS() kms.KeyManager {
	return p.crypto
}

func newWithKMS(k kms.KeyManager) *Packer {
	return New(&provider{
		crypto: k,
	})
}

func TestEncodingType(t *testing.T) {
	// create temporary signing keys for tests
	sigPubKey, sigPrivKey, encPubKey, encPrivKey, err := mockkms.GenerateRawKeys(rand.Reader)
	require.NoError(t, err)

	_, ks := mockkms.CreateKeys(sigPubKey, sigPrivKey, encPubKey, encPrivKey)

	kmsProvider, err := mockkms.NewMockProvider(ks)
	require.NoError(t, err)

	packer := New(kmsProvider)
	require.NotEmpty(t, packer)

	require.Equal(t, encodingType, packer.EncodingType())
}

func retrieveVerKeyByKeySetID(t *testing.T, store storage.Store, keySetID string) string {
	keySetMarshaled, e := store.Get(keySetID)
	require.NoError(t, e)

	var keySet cryptoutil.KeySet
	e = json.Unmarshal(keySetMarshaled, &keySet)
	require.NoError(t, e)

	verKeyID := keySet.PrimaryKey.ID // primaryKey being signature public key
	keyMarshaled, e := store.Get(verKeyID)
	require.NoError(t, e)

	var verKey cryptoutil.Key
	e = json.Unmarshal(keyMarshaled, &verKey)
	require.NoError(t, e)

	return verKey.Value
}

func TestEncrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)
	_, senderKey, e := testingKMS.CreateKeySet()
	require.NoError(t, e)

	t.Run("Failure: pack without any recipients", func(t *testing.T) {
		packer := newWithKMS(testingKMS)
		require.NotEmpty(t, packer)

		_, err := packer.Pack([]byte("Test Message"), base58.Decode(senderKey), [][]byte{})
		require.EqualError(t, err, "empty recipients keys, must have at least one recipient")
	})

	t.Run("Failure: pack with an invalid recipient key", func(t *testing.T) {
		packer := newWithKMS(testingKMS)
		require.NotEmpty(t, packer)

		badKey := "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"

		_, err := packer.Pack([]byte("Test Message"), base58.Decode(senderKey), [][]byte{base58.Decode(badKey)})
		require.EqualError(t, err, "error converting public key")
	})

	_, recipientKey, e := testingKMS.CreateKeySet()
	require.NoError(t, e)

	t.Run("Failure: pack with an invalid-size sender key", func(t *testing.T) {
		packer := newWithKMS(testingKMS)
		require.NotEmpty(t, packer)

		_, err := packer.Pack([]byte("Test Message"), []byte{1, 2, 3}, [][]byte{base58.Decode(recipientKey)})
		require.EqualError(t, err, "3-byte key size is invalid")
	})

	t.Run("Success test case: given keys, generate envelope", func(t *testing.T) {
		packer := newWithKMS(testingKMS)
		require.NotEmpty(t, packer)

		enc, e := packer.Pack([]byte("Pack my box with five dozen liquor jugs!"),
			base58.Decode(senderKey), [][]byte{base58.Decode(recipientKey)})
		require.NoError(t, e)
		require.NotEmpty(t, enc)
	})

	t.Run("Generate testcase with multiple recipients", func(t *testing.T) {
		_, senderKey, err := testingKMS.CreateKeySet()
		require.NoError(t, err)
		_, rec1Key, err := testingKMS.CreateKeySet()
		require.NoError(t, err)
		_, rec2Key, err := testingKMS.CreateKeySet()
		require.NoError(t, err)
		_, rec3Key, err := testingKMS.CreateKeySet()
		require.NoError(t, err)
		_, rec4Key, err := testingKMS.CreateKeySet()
		require.NoError(t, err)

		recipientKeys := [][]byte{
			base58.Decode(rec1Key),
			base58.Decode(rec2Key),
			base58.Decode(rec3Key),
			base58.Decode(rec4Key),
		}
		packer := newWithKMS(testingKMS)

		require.NoError(t, err)
		require.NotEmpty(t, packer)
		enc, err := packer.Pack(
			[]byte("God! a red nugget! A fat egg under a dog!"),
			base58.Decode(senderKey), recipientKeys)
		require.NoError(t, err)
		require.NotEmpty(t, enc)
	})

	t.Run("Pack empty payload using deterministic random source, verify result", func(t *testing.T) {
		senderPub := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		senderPriv := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"

		recipientPub := "CP1eVoFxCguQe1ttDbS3L35ZiJckZ8PZykX1SCDNgEYZ"
		recipientPriv := "5aFcdEMws6ZUL7tWYrJ6DsZvY2GHZYui1jLcYquGr8uHfmyHCs96QU3nRUarH1gVYnMU2i4uUPV5STh2mX7EHpNu"

		kms2, store := newKMS(t)
		err := persistKeys(senderPub, senderPriv, store, store) // using the same store for keystore and metadatastore
		require.NoError(t, err)
		err = persistKeys(recipientPub, recipientPriv, store, store)
		require.NoError(t, err)

		source := insecurerand.NewSource(5937493) // constant fixed to ensure constant output
		constRand := insecurerand.New(source)

		packer := newWithKMS(kms2)
		require.NotEmpty(t, packer)
		packer.randSource = constRand
		enc, err := packer.Pack(nil, base58.Decode(senderPub), [][]byte{base58.Decode(recipientPub)})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRWFYwYUdOeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklqSmlVRFl0VnpaWldXZHpjMlZpVWxOaU0xWlljV0pMTlZWa2FpMDNOSGxGTTFFdFZXaHpjMUF3Vm1aclRHNVhiMFk0WjBSNVVHRkJlREI0VWtGM2NIVWlMQ0pvWldGa1pYSWlPbnNpYTJsa0lqb2lRMUF4WlZadlJuaERaM1ZSWlRGMGRFUmlVek5NTXpWYWFVcGphMW80VUZwNWExZ3hVME5FVG1kRldWb2lMQ0p6Wlc1a1pYSWlPaUpHYzIwMU5WOUNTRkJzVkdsd2RUQlFabEZDY2t0SmRuZ3lTRGw0VTBndFVtbHpXRzgxVVdoemQwTTNjR28yTm5BMVNtOUpVVjlIT1hGdFRrVldNRzVGVG5sTVIwczFlVVZuUzJoeU5ESTBVMnBJYkRWSmQzQnljRnBqYUdGNVprNWtWa2xJTFdKNlprRnhjbXhDWTIxUVZEWkpkR2R4Y3poclRHczlJaXdpYVhZaU9pSm1OV3BVT0VKS2FHeEVZbTQwUWxvMFNGcGZSSEExTkU5TGQyWmxRV1JSTWlKOWZWMTkiLCJpdiI6ImlLZHFxRWpzTktpeW4taGsiLCJ0YWciOiIySm5SbF9iXzM2QS1WaWFKNzNCb1FBPT0ifQ==" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Pack payload using deterministic random source for multiple recipients, verify result", func(t *testing.T) {
		senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
		senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
		senderKMS, senderStore := newKMS(t)
		err := persistKeys(senderPub, senderPriv, senderStore, senderStore)
		require.NoError(t, err)

		rec1Pub := base58.Decode("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs")
		rec2Pub := base58.Decode("G79vtfWgtBG5J7R2QaBQpZfPUQaAab1QJWedWH7q3VK1")
		rec3Pub := base58.Decode("7snUUwA23DVBmafz9ibmBgwFFCUwzgTzmvcJGepuzjmK")
		rec4Pub := base58.Decode("GSRovbnQy8HRjVjvzGbbfN387EX9NFfLj89C1ScXYfrF")

		source := insecurerand.NewSource(6572692) // constant fixed to ensure constant output
		constRand := insecurerand.New(source)

		packer := newWithKMS(senderKMS)
		require.NotEmpty(t, packer)
		packer.randSource = constRand
		enc, err := packer.Pack(
			[]byte("Sphinx of black quartz, judge my vow!"),
			base58.Decode(senderPub),
			[][]byte{rec1Pub, rec2Pub, rec3Pub, rec4Pub})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRWFYwYUdOeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNkltRlliRkl0Umkwd2JEZFZTMU10Vkhwb1MwaGFWMmhIWlMxUU5tbzRlVUYwU2pFeFVEbHlSMU4yVFZGQmNHVnpZbk5wTUVsRE5XVmlVREJoVW5kVFozVWlMQ0pvWldGa1pYSWlPbnNpYTJsa0lqb2lSRVJyTkdGak1scEJNVGxRT0hGWWFtczRXR0ZEV1RsR2VEZFhkMEZ0UTNSRlRHdDRaVVJPY1ZNMlZuTWlMQ0p6Wlc1a1pYSWlPaUk1ZG1oRVdHMXBMWFJVVDBaS1FuRTRXSGhSZUROVmFUVk1SemxIT0ZoRlUxTTBaVjlST0ZCNVFUQlhhR0pCZHkxR2FscFpNVzlRWjJSb1YwOWhPVWRCTlVFd1puSkVVMHBzWm5Nd2VVNDRNVmsxV0V0a1MyUlZOVkJoTlRGdlRuQmFOVlV4VmtKSGQycG1WMmxhU0hOc05DMHhOamhuVG01cGVFazlJaXdpYVhZaU9pSjBUMjlFTW1RMVZrdFdRV2xITlMxNGNqWnFNM1UzTkZWalZUWlVibTlVWHlKOWZTeDdJbVZ1WTNKNWNIUmxaRjlyWlhraU9pSmZZa3RtVUdjM056WnphRmR5TXpWMmVXWm1jV05NZW1oTE1VUlJRV0owWTFaQ1pFVXlNM1ZUVEVGUmRHSkdNVUZMYkRrMmJHcE5WSHBzTmt4d2JuYzBJaXdpYUdWaFpHVnlJanA3SW10cFpDSTZJa2MzT1haMFpsZG5kRUpITlVvM1VqSlJZVUpSY0ZwbVVGVlJZVUZoWWpGUlNsZGxaRmRJTjNFelZrc3hJaXdpYzJWdVpHVnlJam9pVUVWNlZrc3laM1JJU25OcWFuSjVNbEZ3ZG0xYVFXazRSSGRUT1ZrM2RuVkZkakJ3Wm1JdFgyc3pRbmxQUjJoSGRHUmxUMlJUVjJaaVZrazFXRVJuV0UxNFVVWjNNM1prWHpoa2RtUndSMFZDWlZsVlNFbHBRMEZuT0VaNlZqSkNZVkZyWDFCSGRDMUliMjFJVFZoNVp6VTBUbHBCVWtsS2RXNVZQU0lzSW1sMklqb2lVV1ZRU0RRM2FsTkxXVU14Y2pSb1h6QldjMlJJVlRSWU1FZENkME5ZVWtVaWZYMHNleUpsYm1OeWVYQjBaV1JmYTJWNUlqb2lTMVZDU3pWRFIwMU5SR1ZDVkV4dFYwSmZObWQxWVhCSGNWWlZaRUpQTWxFdFkyTkdaVXRHZEZjMWRqZEpUbmhWY1VKa1FWcExlRkpGZWxFMlNEQnpXaUlzSW1obFlXUmxjaUk2ZXlKcmFXUWlPaUkzYzI1VlZYZEJNak5FVmtKdFlXWjZPV2xpYlVKbmQwWkdRMVYzZW1kVWVtMTJZMHBIWlhCMWVtcHRTeUlzSW5ObGJtUmxjaUk2SW1NdFZHRnlTSGgyVW5WTlgybFBTRnBFWkZkbVkwbG1jSGhtYVV3eVdXVlRObk4yYUZKRFRuZGlkMUpxWXpBdFJFZFllbVpTU0RkSVNEaDBOa0ZpYm5SbE1FeG5ZbGd4VGpjelQyMVJUM1ZHVUVkWlQxbFdiRGw2YTFCSlprdzNMWGh4YmtKRVF6Tm5MVkpFU0ZoNlgxSkpSSEp3WWpOVU1VTk9UVDBpTENKcGRpSTZJbGgwYVc5SFUyOWxOR0ZWV1Rac2JYcHNOVkIxWlRkMU9FOWxSMWN4YkVNNEluMTlMSHNpWlc1amNubHdkR1ZrWDJ0bGVTSTZJbEV5Wld4YVQyRktiWFZCYjA5S05GRjJXWE52YVc5R1RsRm9ha2w0UjJSWFZuZHpkV2R3WW05Q1ZucHViVVJHTjB4RFZ6RjNjMUZoTUVwMVpreHFkMjhpTENKb1pXRmtaWElpT25zaWEybGtJam9pUjFOU2IzWmlibEY1T0VoU2FsWnFkbnBIWW1KbVRqTTROMFZZT1U1R1preHFPRGxETVZOaldGbG1ja1lpTENKelpXNWtaWElpT2lKc1NYcGxNR0p3UzJ4cWNuVlRMWGREV21wUWVuWmZRMDAwUW1SdmMweHpNbDlKTUZZeFUxQnZla05uWDA5emNVRTViVEZCUVhoWmVVMXZhVXhvVkUxdU9ERmtPREo2YUd4WmVXVmxVMWxTZVdaSmNUZGFYMTlrTVRNemExcE9Wa054UVdwWFEyRllURmxxVjNoamVIUlNjRFJTYkVwYVlrOUxRVVU5SWl3aWFYWWlPaUpvTUdWTGJtRkZOVXhoWDJKYVpHVkNVR0Z1Vm0wNFpGZFVlRkZEU2xGQ2VpSjlmVjE5IiwiaXYiOiJZb3VDVi1nbGZRaFBhbDc1IiwiY2lwaGVydGV4dCI6Il9jRUNrMDQ3Y2w4Y3dFaUs1UnZLbHZORDJjTlo1bTZBTW9vdlI4MnBpMEhLbzFnZlZBPT0iLCJ0YWciOiJCYWZ4TW1CU2R5bmI0dmxvQ3ptUVNRPT0ifQ==" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})
}

func TestEncryptComponents(t *testing.T) {
	senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
	senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
	rec1Pub := "DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs"

	testKMS, store := newKMS(t)
	e := persistKeys(senderPub, senderPriv, store, store)
	require.NoError(t, e)

	packer := newWithKMS(testKMS)

	t.Run("Failure: content encryption nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(0, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub), [][]byte{base58.Decode(rec1Pub)})
		require.EqualError(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Failure: CEK generation fails", func(t *testing.T) {
		failRand := newFailReader(1, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub), [][]byte{base58.Decode(rec1Pub)})
		require.EqualError(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Failure: recipient nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(2, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack([]byte(
			"Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub), [][]byte{base58.Decode(rec1Pub)})
		require.EqualError(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Failure: recipient sodiumBoxSeal nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(3, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub), [][]byte{base58.Decode(rec1Pub)})
		require.EqualError(t, err, "mock Reader has failed intentionally")
	})

	t.Run("Success: 4 reads necessary for pack", func(t *testing.T) {
		failRand := newFailReader(4, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			base58.Decode(senderPub), [][]byte{base58.Decode(rec1Pub)})
		require.NoError(t, err)
	})

	packer2 := newWithKMS(testKMS)

	t.Run("Failure: generate recipient header with bad sender key", func(t *testing.T) {
		_, err := packer2.buildRecipient(&[32]byte{}, []byte(""), base58.Decode(rec1Pub))
		require.EqualError(t, err, "key is nil")
	})

	t.Run("Failure: generate recipient header with bad recipient key", func(t *testing.T) {
		_, err := packer2.buildRecipient(&[32]byte{}, base58.Decode(senderPub), base58.Decode("AAAA"))
		require.EqualError(t, err, "3-byte key size is invalid")
	})
}

func TestDecrypt(t *testing.T) {
	senderKMS, mockStore := newKMS(t)
	senderKeySetID, senderKeyB58, err := senderKMS.CreateKeySet()
	require.NoError(t, err)

	senderKey := retrieveVerKeyByKeySetID(t, mockStore, senderKeySetID)
	require.Equal(t, senderKey, senderKeyB58)

	recKeySetID, recKeyB58, err := senderKMS.CreateKeySet()
	require.NoError(t, err)

	recKey := retrieveVerKeyByKeySetID(t, mockStore, recKeySetID)
	require.NoError(t, err)
	require.Equal(t, recKey, recKeyB58)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMS(senderKMS)
		require.NoError(t, err)

		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		enc, err := packer.Pack(msgIn, base58.Decode(senderKey), [][]byte{base58.Decode(recKey)})
		require.NoError(t, err)
		msgOut, err := packer.Unpack(enc)
		require.NoError(t, err)

		require.ElementsMatch(t, msgIn, msgOut)
	})

	t.Run("Success: pack and unpack, different packers, including fail recipient who wasn't sent the message", func(t *testing.T) { // nolint: lll
		rec1KMS, newMockStore1 := newKMS(t)
		rec1KeySetID, rec1KeyB58, err := rec1KMS.CreateKeySet()
		require.NoError(t, err)

		rec1Key := retrieveVerKeyByKeySetID(t, newMockStore1, rec1KeySetID)
		require.NoError(t, err)
		require.Equal(t, rec1Key, rec1KeyB58)

		rec2KMS, newMockStore2 := newKMS(t)
		rec2KeySetID, rec2KeyB58, err := rec2KMS.CreateKeySet()
		require.NoError(t, err)

		rec2Key := retrieveVerKeyByKeySetID(t, newMockStore2, rec2KeySetID)
		require.NoError(t, err)
		require.Equal(t, rec2Key, rec2KeyB58)

		rec3KMS, newMockStore3 := newKMS(t)
		rec3KeySetID, rec3KeyB58, err := rec3KMS.CreateKeySet()
		require.NoError(t, err)

		rec3Key := retrieveVerKeyByKeySetID(t, newMockStore3, rec3KeySetID)
		require.NoError(t, err)
		require.Equal(t, rec3Key, rec3KeyB58)

		sendPacker := newWithKMS(senderKMS)
		rec2Packer := newWithKMS(rec2KMS)

		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		enc, err := sendPacker.Pack(msgIn, base58.Decode(senderKey),
			[][]byte{base58.Decode(rec1Key), base58.Decode(rec2Key), base58.Decode(rec3Key)})
		require.NoError(t, err)
		msgOut, err := rec2Packer.Unpack(enc)
		require.NoError(t, err)
		require.ElementsMatch(t, msgIn, msgOut)

		emptyKMS, _ := newKMS(t)
		rec4Packer := newWithKMS(emptyKMS)

		_, err = rec4Packer.Unpack(enc)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})

	t.Run("Test unpacking python envelope", func(t *testing.T) {
		env := `{"protected": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMCIsICJhbGciOiAiQXV0aGNyeXB0IiwgInJlY2lwaWVudHMiOiBbeyJlbmNyeXB0ZWRfa2V5IjogIkVhTVl4b3RKYjg4Vmt2ZmxNN1htajdFUzdvVVVSOEJSWWZ1akJGS1FGT3Y4Q2o3c0F2RndVWE5QdWVWanZ0SkEiLCAiaGVhZGVyIjogeyJraWQiOiAiRjdtTnRGMmZyTHVSdTJjTUVqWEJuV2RZY1RaQVhOUDlqRWtwclh4aWFaaTEiLCAic2VuZGVyIjogInJna1lWLUlxTWxlQUNkdE1qYXE4YnpwQXBKLXlRbjdWdzRIUnFZODNJVFozNzJkc0Y5RzV6bTVKMGhyNDVuSzBnS2JUYzRRYk5VZ1NreUExUlpZbEl6WHBwanN5eGdZUkU5ek9IbUFDcF9ldWZzejZ4YUxFOVRxN01KVT0iLCAiaXYiOiAiQ04wZWd4TFM2R19oUThDVXBjZkdZWmxzNjFtMm9YUVQifX1dfQ==", "iv": "Y4osZIg1IWaa1kFb", "ciphertext": "m9otQmcqYHOxZh4XfLbdCNouqnuPz7lGtcL5ga_1PZcPZDrhnGWPyLW2rPN2lRTftyYGPPT3tOlu4GFecZIz4zXI9kdz", "tag": "CoV9tCdrFnBbVe2h-pYyhQ=="}` // nolint: lll

		msg := "Yvgu yrf vy jgbuffi tvjc hgsj fhlusfm hsuf tiw fun s kb si kfuh bssnc"

		recPub := "F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"
		recPriv := "2nYsWTQ1ZguQ7G2HYfMWjMNqWagBQfaKB9GLbsFk7Z7tKVBEr2arwpVKDwgLUbaxguUzQuf7o67aWKzgtHmKaypM"

		recKMS, store := newKMS(t)
		err := persistKeys(recPub, recPriv, store, store)
		require.NoError(t, err)

		recPacker := newWithKMS(recKMS)

		msgOut, err := recPacker.Unpack([]byte(env))
		require.NoError(t, err)
		require.ElementsMatch(t, []byte(msg), msgOut)
	})

	t.Run("Test unpacking python envelope with multiple recipients", func(t *testing.T) {
		env := `{"protected": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMCIsICJhbGciOiAiQXV0aGNyeXB0IiwgInJlY2lwaWVudHMiOiBbeyJlbmNyeXB0ZWRfa2V5IjogImd4X3NySTljSEtNTEJnaktNOTlybUx3alFZUjJxVTdMOXc0QWo3Z1lTbDJvUTRubE5WN2tZSmJ0bVFlaWVueE8iLCAiaGVhZGVyIjogeyJraWQiOiAiQ2ZGUmluZDh0eGYxOHJmVHl1aE1pZ2t4UVBhbVNUb3hVM2prdW5ldjR5dnUiLCAic2VuZGVyIjogImFWRW03ak5Kajg2Zm9NM0VYaXZjYWpOWlFnN3pGUm0wTnk5ZzdZTzFueUpvblI2bmNVaV9EZWZzWVBHa25KcG1ZbFhuRDIzVU5nLXNBN1lWUnh5WW15aFZBSm5XNWZwdjBuNE5jaFdBTjl5S3pIMTd3NjZQLVV2WjVDcz0iLCAiaXYiOiAieVB0NGhHZVpObWFLN0hMMGtoWjhreFJzQjc3c3BOX2UifX0sIHsiZW5jcnlwdGVkX2tleSI6ICJ3a3RrWjY3VDR4R2NjTW1GZnRIRmNEV2FZMVQxRFQ3YURhMHBPeUpqTHU2REU2UGVKMUhuVXlRWXlOZ2VPR3ExIiwgImhlYWRlciI6IHsia2lkIjogIko1c2hTVlo2QW9DWHFxWWROR2tVdjFDTWZRYWVLRnNGRU4zaFdwNVBLVEN3IiwgInNlbmRlciI6ICJWdEQtakZfZFNDbmVxOUtTcVB0SUtHbHdHb0FzVHB0UkhzMTRYaWhNR0U4LUh4SjU5aVhtSnVLellxTjM2b19ZOWxfYmRFT1pRSjN0R2tRX1BqbTJyQ3VqWkRIbjdDS3Fsd3N4QlNVemYweW43aWliaDFQazJ6R0wyb2M9IiwgIml2IjogIm5acW1CbzBfT2QyTHlXejlHclJJMUlhWlRXUk4zbGVBIn19LCB7ImVuY3J5cHRlZF9rZXkiOiAiUlBsQWtTS1NsdFpGeEFJc1VzbWNiUVVMUTJWWHhRT2kzUEIxelhTbGs3TlBtMkZ2TE9zVDdQSEFHQU5Hem5oNiIsICJoZWFkZXIiOiB7ImtpZCI6ICJCS3ZqbUZFYkMyYjF3YkVycUN4R2syYmdxdkc5dUx3UlU5cWdOS3lINXRURiIsICJzZW5kZXIiOiAiTVhvRXl0NlZULXVFQnFzWEM1SWF1VXdZYXFxakxIYTdWWlF0NGRJX3FBaFZHVWhUTi01c004cXB6TnBnQlpUUHJrazFSMlBnbjlraU4waEpTUXk1T0FmOGdkSE43YXRTVDhUWEtMSHJNdm4wcDcyNUNUd3pZVnZFVnlNPSIsICJpdiI6ICJPb2FTVWgycVdOVk5qWVV6ZnZTNTdCQ1RnY3ZQYVhMeCJ9fSwgeyJlbmNyeXB0ZWRfa2V5IjogImY1cXV2amt1c2l6TmtRcm9HMk51akFsa0NzbllleUF1R1pMWDZmXy1DeG4taUNENjI2akp0aEk4OFBSei1TWWUiLCAiaGVhZGVyIjogeyJraWQiOiAiRWZ3cFR3aFVSU0QzY3lxanNWYlNWU0VMeU4yN250Tlk4V3dhZHNnVUNEOW0iLCAic2VuZGVyIjogImlOMDJNRzllSEpZZmQ3V3pGd1VFeWJBNmFWeU1Ma1JHcXVhYlJGQnJobFU3Q29EMzFHdW5yTWhEWTZETGFJV0FoX2dPMVRLMWtpMzYtTzQ4TlEyZGdOLU1RdS0wZTV5V2dQS1dzV1MtQ2xPbllEQ0RpVkc1VHBJS2dpVT0iLCAiaXYiOiAiZUg0cDZOX0dGNnpzU2trQk5nY0dWN3RRQkxfRl93MS0ifX0sIHsiZW5jcnlwdGVkX2tleSI6ICJqa3FnbHlmUlNWSXZqVnpkZ04wSGN4SGVzMTBoTjE3ckJLejZhcUtlczR3UTRLWGNGYjNpa3pNSmFSWHAwblVSIiwgImhlYWRlciI6IHsia2lkIjogIkFROW5IdExubXVHODFweTY0WUc1Z2VGMnZkNWhRQ0tIaTVNcnFRMUxZQ1hFIiwgInNlbmRlciI6ICJpSXJFOVUyOUVUbTRWa045aFdvYy1UN0dGYjVrdHB4SGtGeWp6d3BLcDJ5MWh2WWQ0NDF0SzdFUXlhTXhHeG9KNklMaWFHNnNpbTF4WS05UHV2Ny03clB4QTFCb3FxMTY0VzJZZU9FRjFwbnBOV2VmYmdTc1dtQUk0QlU9IiwgIml2IjogIm03S2h3THJ1OGtyQ1VXN1BiNTczZWpGblI3Ymlod3lNIn19XX0=", "iv": "1_pOOQhySyaYcVxi", "ciphertext": "CYHrOg1HeNxhUECoRIQRLNAOXwAjagUYf0xLp0Knnj6mEALg8lFbfmoh_oDptJ4El8jVbgDLiBExaEXIxYVnR7DR-hZjxjdbOBQAOAMUYnnvAk0lHJM0KBWlhE0AWrek1JlAfTnq-L6VsCXEqGYHg1uvpBIJicE=", "tag": "l1KfDt-VQIAImCTl7SA2og=="}` // nolint: lll

		msg := "Iiwufh utiweuop fji olioy pio omlim, om kutxrwu gvgbkn kutxr " +
			"w srt luhsnehim. Igywenomwe fji omwuie fnomhwuie, fjimwef."

		recPub := "AQ9nHtLnmuG81py64YG5geF2vd5hQCKHi5MrqQ1LYCXE"
		recPriv := "2YbSVZzSVaim41bWDdsBzamrhXrPFKKEpzXZRmgDuoFJco5VQELRSj1oWFR9aRdaufsdUyw8sozTtZuX8Mzsqboz"

		recKMS, store := newKMS(t)
		err := persistKeys(recPub, recPriv, store, store)
		require.NoError(t, err)

		recPacker := newWithKMS(recKMS)

		msgOut, err := recPacker.Unpack([]byte(env))
		require.NoError(t, err)
		require.ElementsMatch(t, []byte(msg), msgOut)
	})

	t.Run("Test unpacking python envelope with invalid recipient", func(t *testing.T) {
		env := `{"protected": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMCIsICJhbGciOiAiQXV0aGNyeXB0IiwgInJlY2lwaWVudHMiOiBbeyJlbmNyeXB0ZWRfa2V5IjogIjdzN0ZTRXR6Sy1vTzdSWmdISklsSTlzX1lVU2xkMUpnRldPeUNhYUdGY1Y0aHBSTWxQbG0wNDBFcUJXRWVwY3oiLCAiaGVhZGVyIjogeyJraWQiOiAiN0RLbk56TWJHRWNYODYxOGp2WWtiNlhQTFR6eXU2YnhSbTh3RnhZb0d3SHEiLCAic2VuZGVyIjogInFLYTRDeXV1OXZOcmJzX1RCLXhQWXI2aFg2cXJZLTM4Vjd4VXdOQjFyd0J1TjVNTUVJYmRERDFvRElhV2o0QUpSYUZDTEVhSzMtakFSZHBsR1UtM2d4TWY2dkpRZWhiZkZhZHNwemdxRE9iWFZDWUJONGxrVXZLZWhvND0iLCAiaXYiOiAiSWFqeVdudFdSMENxS1BYUWJpWWptbWJRWFNNTEp2X1UifX0sIHsiZW5jcnlwdGVkX2tleSI6ICJZa05vVGh2ZUlIcC13NGlrRW1kQU51VHdxTEx1ZjBocVlVbXRJc2c5WlJMd1BKaUZHWVZuTXl1ZktKZWRvcmthIiwgImhlYWRlciI6IHsia2lkIjogIjdDRURlZUpZTnlRUzhyQjdNVHpvUHhWYXFIWm9ZZkQxNUVIVzhaVVN3VnVhIiwgInNlbmRlciI6ICJ3ZEhjc1hDemdTSjhucDRFU0pDcmJ5OWNrNjJaUEFFVjhJRjYwQmotaUhhbXJLRnBKOTJpZVNTaE1JcTdwdTNmQWZQLWo5S3J6ajAwMEV0SXB5cm05SmNrM0QwSnRBcmtYV2VsSzBoUF9ZeDR4Vlc5dW43MWlfdFBXNWM9IiwgIml2IjogIkRlbUlJbHRKaXd5TU1faGhIS29kcTZpQkx4Q1J5Z2Z3In19XX0=", "iv": "BKWHs6z0UHxGddwg", "ciphertext": "YC2eQQPYVjPHj3wIxUXxBj0yXFLuRN5Lc-9WM8hY6TXoekh-ca9-UWbHasikbcxyukTT3e-QiteOilG-6X7e9x4wiQmWn_NFLOLrqoFe669JIbkgvjHYwuQEQkIVfbD-2woSxsMUl9yln5RS-NssI5cEIVH_C1w=", "tag": "M8GPexbguDoZk5L51AvLjA=="}` // nolint: lll

		recPub := "A3KnccxQu27yWQrSLwA2YFbfoSs4CHo3q6LjvhmpKz9h"
		recPriv := "49Y63zwonNoj2jEhMYE22TDwQCn7RLKMqNeSkSoBBucbAWceJuXXNCACXfpbXD7PHKM13SWaySyDukEakPVn5sWs"

		recKMS, store := newKMS(t)
		err := persistKeys(recPub, recPriv, store, store)
		require.NoError(t, err)

		recPacker := newWithKMS(recKMS)

		_, err = recPacker.Unpack([]byte(env))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})
}

func unpackComponentFailureTest(t *testing.T, protectedHeader, msg string, recKeyPub, recKeyPriv *cryptoutil.Key,
	errString string) {
	fullMessage := `{"protected": "` + base64.URLEncoding.EncodeToString([]byte(protectedHeader)) + "\", " + msg

	w, s := newKMS(t)

	err := persistKeys(recKeyPub.Value, recKeyPriv.Value, s, s)
	if err != nil {
		require.Contains(t, err.Error(), errString)
		return
	}

	recPacker := newWithKMS(w)
	_, err = recPacker.Unpack([]byte(fullMessage))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), errString)
}

func TestUnpackComponents(t *testing.T) {
	recKeyPub, recKeyPriv := getB58Key("Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v",
		"5pG8rLcp9WqPXQLSyQetPiyTEnLuanjS2TGd7h4DqutY6gNbLD6pnvT3H8nC5K9vEjy1UJdTtwaejf1xqDyhCrzr")

	t.Run("Fail: non-JSON envelope", func(t *testing.T) {
		msg := `ed": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEu"}`

		w, s := newKMS(t)
		err := persistKeys(recKeyPub.Value, recKeyPriv.Value, s, s)
		require.NoError(t, err)

		recPacker := newWithKMS(w)

		_, err = recPacker.Unpack([]byte(msg))
		require.EqualError(t, err, "invalid character 'e' looking for beginning of value")
	})

	t.Run("Fail: non-base64 protected header", func(t *testing.T) {
		msg := `{"protected": "&**^(&^%", "iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}` // nolint: lll

		w, s := newKMS(t)
		err := persistKeys(recKeyPub.Value, recKeyPriv.Value, s, s)
		require.NoError(t, err)

		recPacker := newWithKMS(w)

		_, err = recPacker.Unpack([]byte(msg))
		require.EqualError(t, err, "illegal base64 data at input byte 0")
	})

	t.Run("Fail: header not json", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`}eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMC`,
			`"not important":[]}`,
			recKeyPub,
			recKeyPriv,
			"invalid character '}' looking for beginning of value")
	})

	t.Run("Fail: bad 'typ' field", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JSON", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                     // nolint: lll
			recKeyPub,
			recKeyPriv,
			"message type JSON not supported")
	})

	t.Run("Fail: anoncrypt not supported", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Anoncrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                        //nolint: lll
			recKeyPub,
			recKeyPriv,
			"message format Anoncrypt not supported")
	})

	t.Run("Fail: no recipients in header", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": []}`,
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			recKeyPub,
			recKeyPriv,
			"no key accessible")
	})

	t.Run("Fail: invalid public key", func(t *testing.T) {
		recPub, recPriv := getB58Key("6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7", // invalid key, won't convert
			"5pG8rLcp9WqPXQLSyQetPiyTEnLuanjS2TGd7h4DqutY6gNbLD6pnvT3H8nC5K9vEjy1UJdTtwaejf1xqDyhCrzr")

		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                        // nolint: lll
			recPub,
			recPriv,
			"error converting public key")
	})

	t.Run("Fail: invalid public key", func(t *testing.T) {
		recPub, recPriv := getB58Key("57N4aoQKaxUGNeEn3ETnTKgeD1L5Wm3U3Vb8qi3hupLn", // mismatched keypair, won't decrypt
			"5pG8rLcp9WqPXQLSyQetPiyTEnLuanjS2TGd7h4DqutY6gNbLD6pnvT3H8nC5K9vEjy1UJdTtwaejf1xqDyhCrzr")

		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "57N4aoQKaxUGNeEn3ETnTKgeD1L5Wm3U3Vb8qi3hupLn", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                        // nolint: lll
			recPub,
			recPriv,
			"failed to unpack")
	})

	t.Run("Sender is invalid base64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "*^&", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                               // nolint: lll
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Sender is invalid public key", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "7ZA_k_bM4FRp6jY_LNzv9pjuOh1NbVlbBA-yTjzsc22HnPKPK8_MKUNU1Rlt0woNUNWLZI4ShBD_th14ULmTjggBI8K4A8efTI4efxv5xTYEemj9uVPvvLKs4Go=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                        // nolint: lll
			recKeyPub,
			recKeyPriv,
			"error converting public key")
	})

	t.Run("Message auth fail, protected header has extra whitespace", func(t *testing.T) {
		unpackComponentFailureTest(t,
			` {"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                                                         // nolint: lll
			recKeyPub,
			recKeyPriv,
			"chacha20poly1305: message authentication failed")
	})

	t.Run("Nonce is invalid base64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "(^_^)"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                                             // nolint: lll
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Encrypted CEK is invalid base64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "_-", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                          // nolint: lll
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Bad encrypted key cannot be decrypted", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_W", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                                                                                                                // nolint: lll
			recKeyPub,
			recKeyPriv,
			"failed to decrypt CEK")
	})

	// valid protected header for envelope being used
	prot := `{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Authcrypt", "recipients": [{"encrypted_key": "DaZGim_WCyntSdziFgnQanpQlR_tVHzHznGbW-yhTYDVgGuc5nr6J5svu7dQbBg3", "header": {"kid": "Ak528pLhb6DNFrGWY6HjMUjpNV613h2qtAJ47j1FYe8v", "sender": "wZ4cC42eDMeLApmJvJC4INbuKINzdZZECGHpWDgsrmBURPJN_bWOkUV3E6oORN4ILAf_xEuWefS4b_goRycCogkZvTyS1HgvBtx2YO1A2q-a7tp__08Ky4qtSiY=", "iv": "A818WMvddPrZ8mmYqp2iuu8gqoZZC2Hx"}}]}` // nolint: lll

	t.Run("Ciphertext nonce not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv": "!!!!!", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Ciphertext not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot, `"iv": "oDZpVO648Po3UcoW", "ciphertext": "=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Ciphertext tag not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "123"}`, // nolint: lll
			recKeyPub,
			recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	badKeyPub := &cryptoutil.Key{
		Value: "badkeyabcdefghijklmnopqrstuvwxyz",
	}
	badKeyPriv := &cryptoutil.Key{
		Value: "badkeyabcdefghijklmnopqrstuvwxyzbadkeyabcdefghijklmnopqrstuvwxyz",
	}

	t.Run("Recipient Key not valid key", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			badKeyPub,
			badKeyPriv,
			"key is nil")
	})
}

func Test_getCEK(t *testing.T) {
	k := mockkms.CloseableKMS{
		FindVerKeyValue:  0,
		EncryptionKeyErr: fmt.Errorf("mock error"),
	}

	recs := []recipient{
		{
			EncryptedKey: "",
			Header: recipientHeader{
				KID: "BADKEY",
			},
		},
	}

	_, err := getCEK(recs, &k)
	require.EqualError(t, err, "mock error")
}

func getB58Key(pub, priv string) (*cryptoutil.Key, *cryptoutil.Key) {
	keyHash := sha256.Sum256([]byte(pub))

	keyPub := cryptoutil.Key{
		ID:    base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("sp")...)),
		Value: pub,
	}
	keyPriv := cryptoutil.Key{
		ID:    base64.RawURLEncoding.EncodeToString(append(keyHash[:], []byte("ss")...)),
		Value: priv,
	}

	return &keyPub, &keyPriv
}
