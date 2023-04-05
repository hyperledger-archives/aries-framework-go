/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package anoncryt

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	insecurerand "math/rand"
	"testing"

	"github.com/btcsuite/btcutil/base58"
	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
	mockStorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// failReader wraps a Reader, used for testing different failure checks for encryption tests.
//	count: count the number of Reads called before the failWriter fails.
type failReader struct {
	count int
	data  io.Reader
}

// newFailReader constructs a failWriter.
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
	kms           kms.KeyManager
	cryptoService cryptoapi.Crypto
}

func (p *provider) StorageProvider() storage.Provider {
	return p.storeProvider
}

func (p *provider) Crypto() cryptoapi.Crypto {
	return p.cryptoService
}

type kmsProvider struct {
	store             kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.store
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

func newKMS(t *testing.T) (kms.KeyManager, storage.Store) {
	msp := mockStorage.NewMockStoreProvider()
	p := &provider{storeProvider: msp}

	store, err := p.StorageProvider().OpenStore("test-kms")
	require.NoError(t, err)

	kmsStore, err := kms.NewAriesProviderWrapper(msp)
	require.NoError(t, err)

	kmsProv := &kmsProvider{
		store:             kmsStore,
		secretLockService: &noop.NoLock{},
	}

	customKMS, err := localkms.New("local-lock://primary/test/", kmsProv)
	require.NoError(t, err)

	return customKMS, store
}

func persistKey(t *testing.T, pub, priv string, km kms.KeyManager) error {
	t.Helper()

	kid, err := jwkkid.CreateKID(base58.Decode(pub), kms.ED25519Type)
	if err != nil {
		return err
	}

	edPriv := ed25519.PrivateKey(base58.Decode(priv))
	if len(edPriv) == 0 {
		return fmt.Errorf("error converting bad public key")
	}

	k1, _, err := km.ImportPrivateKey(edPriv, kms.ED25519Type, kms.WithKeyID(kid))
	require.NoError(t, err)
	require.Equal(t, kid, k1)

	return nil
}

func (p *provider) KMS() kms.KeyManager {
	return p.kms
}

func newWithKMSAndCrypto(t *testing.T, k kms.KeyManager) *Packer {
	c, err := tinkcrypto.New()
	require.NoError(t, err)

	return New(&provider{
		kms:           k,
		cryptoService: c,
	})
}

func (p *provider) VDRegistry() vdrapi.Registry {
	return nil
}

func createKey(t *testing.T, km kms.KeyManager) []byte {
	_, key, err := km.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	return key
}

func TestEncodingType(t *testing.T) {
	testKMS, store := newKMS(t)
	require.NotEmpty(t, testKMS)

	packer := New(&provider{
		storeProvider: mockStorage.NewCustomMockStoreProvider(store),
		kms:           testKMS,
	})
	require.NotEmpty(t, packer)

	require.Equal(t, encodingType, packer.EncodingType())
}

func TestEncrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)

	t.Run("Failure: pack without any recipients", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		_, err := packer.Pack("", []byte("Test Message"), []byte{}, [][]byte{})
		require.EqualError(t, err, "empty recipients keys, must have at least one recipient")
	})

	t.Run("Failure: pack with an invalid recipient key", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		badKey := "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"

		_, err := packer.Pack("", []byte("Test Message"), []byte{}, [][]byte{base58.Decode(badKey)})
		require.EqualError(t, err, "pack: failed to build recipients: recipients keys are empty")
	})

	recipientKey := createKey(t, testingKMS)

	t.Run("Success: given keys, generate envelope", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		enc, e := packer.Pack("", []byte("Pack my box with five dozen liquor jugs!"),
			[]byte{}, [][]byte{recipientKey})
		require.NoError(t, e)
		require.NotEmpty(t, enc)
	})

	t.Run("Success: with multiple recipients", func(t *testing.T) {
		rec1Key := createKey(t, testingKMS)
		rec2Key := createKey(t, testingKMS)
		rec3Key := createKey(t, testingKMS)
		rec4Key := createKey(t, testingKMS)

		recipientKeys := [][]byte{rec1Key, rec2Key, rec3Key, rec4Key}
		packer := newWithKMSAndCrypto(t, testingKMS)
		require.NotEmpty(t, packer)

		enc, err := packer.Pack("", []byte("God! a red nugget! A fat egg under a dog!"), []byte{}, recipientKeys)
		require.NoError(t, err)
		require.NotEmpty(t, enc)
	})

	t.Run("Success: pack empty payload using deterministic random source, verify result", func(t *testing.T) {
		senderPub := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		senderPriv := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"

		recipientPub := "CP1eVoFxCguQe1ttDbS3L35ZiJckZ8PZykX1SCDNgEYZ"
		recipientPriv := "5aFcdEMws6ZUL7tWYrJ6DsZvY2GHZYui1jLcYquGr8uHfmyHCs96QU3nRUarH1gVYnMU2i4uUPV5STh2mX7EHpNu"

		kms2, _ := newKMS(t)
		require.NoError(t, persistKey(t, senderPub, senderPriv, kms2))
		require.NoError(t, persistKey(t, recipientPub, recipientPriv, kms2))

		source := insecurerand.NewSource(5937493) // constant fixed to ensure constant output
		constRand := insecurerand.New(source)     //nolint:gosec

		packer := newWithKMSAndCrypto(t, kms2)
		require.NotEmpty(t, packer)
		packer.randSource = constRand
		enc, err := packer.Pack("", nil, []byte{}, [][]byte{base58.Decode(recipientPub)})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRVzV2Ym1OeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklsWXRUMXBaUXpjdFNucEpVVFZGYUhCYWVIb3dTV0ZDTXkxWlZFNXhUbkZ5Y0RaRmVFVXRlbDlNUjFaaldVOVRPRkpaVkZGYVYwcHllVXRRUkU5bU5FNWtTRTVRV0VsQ1JXMUxVbEZoVURscGVGcGlNbUp0VUdnemJuZHlTR0l6VkZFelNWbExZbnBvT0ROdlBTSXNJbWhsWVdSbGNpSTZleUpyYVdRaU9pSkRVREZsVm05R2VFTm5kVkZsTVhSMFJHSlRNMHd6TlZwcFNtTnJXamhRV25scldERlRRMFJPWjBWWldpSjlmVjE5IiwiaXYiOiJpS2RxcUVqc05LaXluLWhrIiwidGFnIjoiR3FVZHVhamVfSHNLS3c3QXJ3dnQ0Zz09In0=" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})

	t.Run("Success: pack payload using deterministic random source for multiple recipients, verify result", func(t *testing.T) { // nolint: lll
		senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
		senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
		senderKMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, senderPub, senderPriv, senderKMS))

		rec1Pub := base58.Decode("DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs")
		rec2Pub := base58.Decode("G79vtfWgtBG5J7R2QaBQpZfPUQaAab1QJWedWH7q3VK1")
		rec3Pub := base58.Decode("7snUUwA23DVBmafz9ibmBgwFFCUwzgTzmvcJGepuzjmK")
		rec4Pub := base58.Decode("GSRovbnQy8HRjVjvzGbbfN387EX9NFfLj89C1ScXYfrF")

		source := insecurerand.NewSource(6572692) // constant fixed to ensure constant output
		constRand := insecurerand.New(source)     //nolint:gosec

		packer := newWithKMSAndCrypto(t, senderKMS)
		require.NotEmpty(t, packer)
		packer.randSource = constRand
		enc, err := packer.Pack(
			"",
			[]byte("Sphinx of black quartz, judge my vow!"),
			[]byte{},
			[][]byte{rec1Pub, rec2Pub, rec3Pub, rec4Pub})
		require.NoError(t, err)

		test := "eyJwcm90ZWN0ZWQiOiJleUpsYm1NaU9pSmphR0ZqYUdFeU1IQnZiSGt4TXpBMVgybGxkR1lpTENKMGVYQWlPaUpLVjAwdk1TNHdJaXdpWVd4bklqb2lRVzV2Ym1OeWVYQjBJaXdpY21WamFYQnBaVzUwY3lJNlczc2laVzVqY25sd2RHVmtYMnRsZVNJNklubFdTWEJ0VTFaSWEyVm9hVXRRWm1GQmRVNW1OMUpyT1c5cmJqTk9WMHhCWjBRM1NVTkNVVVpZVkVnMmN6WXRUbFpRWWtwRE1GQk9OR1ozTkZkZmVWSXpPVVpJTlU1QlJVNW9OMlpOWTBacFdYSmZNbGhCZVhwb1FubG1lRkZ6ZUhCSVh6ZEtkR00yTlVoblBTSXNJbWhsWVdSbGNpSTZleUpyYVdRaU9pSkVSR3MwWVdNeVdrRXhPVkE0Y1ZocWF6aFlZVU5aT1VaNE4xZDNRVzFEZEVWTWEzaGxSRTV4VXpaV2N5SjlmU3g3SW1WdVkzSjVjSFJsWkY5clpYa2lPaUpuZW5ScFpHeFpjWGwwUlRSb2RHczFSbTR3V21KSlRFUnJZbFZZV210WVJqTkZOUzFMTkY5dk1sWlNhREZUZUhkb2JEZHNNbWxTU20xVE1ISmlNREpxWTBaU2QwUkNkMmxxUzFWS1JYbDFTek0yYTBneldXTnRRbVl5UzFGdFVXbE1lR05KUlRoRGEzVkdRVDBpTENKb1pXRmtaWElpT25zaWEybGtJam9pUnpjNWRuUm1WMmQwUWtjMVNqZFNNbEZoUWxGd1dtWlFWVkZoUVdGaU1WRktWMlZrVjBnM2NUTldTekVpZlgwc2V5SmxibU55ZVhCMFpXUmZhMlY1SWpvaVdFdEZWMkZ3YUVzelFTMXBiRVZLTFVwNlVtdFhaRTAwZUVKcFRtTXRXa1ZvVlZwNmRVdFZSVlI2WDFSWlJqRXdSWFZNUXpoZmNHUlVUMUV6VlROSmExVmhMV0ZGUkhGalluZFpSM05VVEVkQlVWVXdZVWh4YlhWbVNHUXRUamxRVTJaVVFuVklWRTVuTFRROUlpd2lhR1ZoWkdWeUlqcDdJbXRwWkNJNklqZHpibFZWZDBFeU0wUldRbTFoWm5vNWFXSnRRbWQzUmtaRFZYZDZaMVI2YlhaalNrZGxjSFY2YW0xTEluMTlMSHNpWlc1amNubHdkR1ZrWDJ0bGVTSTZJblZwTFhFMGJtRmtRVzF5VDFSZmVteE5OWFZHWWpCT1kzRTBaV3h5YVhkQ1gwUk5kRmhsV0U5cGVIazFRblZoYW01S2RHdzVja2RvZDJONlltWmZjbEZ0WTJadUxVMUhXR3BFYlROb1NYUkVjWGQ0YmpoWmVEWnROVUU1T1V4NVdtcHBaemhVTW1OeFoycHJQU0lzSW1obFlXUmxjaUk2ZXlKcmFXUWlPaUpIVTFKdmRtSnVVWGs0U0ZKcVZtcDJla2RpWW1aT016ZzNSVmc1VGtabVRHbzRPVU14VTJOWVdXWnlSaUo5ZlYxOSIsIml2IjoiWW91Q1YtZ2xmUWhQYWw3NSIsImNpcGhlcnRleHQiOiJfY0VDazA0N2NsOGN3RWlLNVJ2S2x2TkQyY05aNW02QU1vb3ZSODJwaTBIS28xZ2ZWQT09IiwidGFnIjoiNmpZR2xreEdaRXp0ME5yQ1lkcFVLUT09In0=" // nolint: lll

		require.Equal(t, test, base64.URLEncoding.EncodeToString(enc))
	})
}

func TestEncryptComponents(t *testing.T) {
	senderPub := "9NKZ9pHL9YVS7BzqJsz3e9uVvk44rJodKfLKbq4hmeUw"
	senderPriv := "2VZLugb22G3iovUvGrecKj3VHFUNeCetkApeB4Fn4zkgBqYaMSFTW2nvF395voJ76vHkfnUXH2qvJoJnFydRoQBR"
	recPub := "DDk4ac2ZA19P8qXjk8XaCY9Fx7WwAmCtELkxeDNqS6Vs"

	testKMS, _ := newKMS(t)
	require.NoError(t, persistKey(t, senderPub, senderPriv, testKMS))

	packer := newWithKMSAndCrypto(t, testKMS)

	t.Run("Failure: content encryption nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(0, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			"",
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			[]byte{}, [][]byte{base58.Decode(recPub)})
		require.EqualError(t, err, "pack: failed to generate random nonce: mock Reader has failed intentionally")
	})

	t.Run("Failure: CEK generation fails", func(t *testing.T) {
		failRand := newFailReader(1, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			"",
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			[]byte{}, [][]byte{base58.Decode(recPub)})
		require.EqualError(t, err, "pack: failed to generate cek: mock Reader has failed intentionally")
	})

	t.Run("Failure: recipient nonce generation fails", func(t *testing.T) {
		failRand := newFailReader(2, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			"", []byte(
				"Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			[]byte{}, [][]byte{base58.Decode(recPub)})
		require.EqualError(t, err, "pack: failed to build recipients: recipients keys are empty")
	})

	t.Run("Success: 3 reads necessary for pack", func(t *testing.T) {
		failRand := newFailReader(3, rand.Reader)
		packer.randSource = failRand

		_, err := packer.Pack(
			"",
			[]byte("Lorem Ipsum Dolor Sit Amet Consectetur Adispici Elit"),
			[]byte{}, [][]byte{base58.Decode(recPub)})
		require.NoError(t, err)
	})
}

func TestDecrypt(t *testing.T) {
	testingKMS, _ := newKMS(t)

	_, recKey, err := testingKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
	require.NoError(t, err)

	t.Run("Success: pack then unpack, same packer", func(t *testing.T) {
		packer := newWithKMSAndCrypto(t, testingKMS)
		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = packer.Pack("", msgIn, []byte{}, [][]byte{recKey})
		require.NoError(t, err)
		env, err = packer.Unpack(enc)
		require.NoError(t, err)

		require.ElementsMatch(t, msgIn, env.Message)
		require.Equal(t, recKey, env.ToKey)
	})

	t.Run("Success: pack and unpack, different packers, including fail recipient who wasn't sent the message", func(t *testing.T) { // nolint: lll
		rec1KMS, _ := newKMS(t)
		rec1Key := createKey(t, rec1KMS)

		rec2KMS, _ := newKMS(t)
		rec2Key := createKey(t, rec2KMS)

		rec3KMS, _ := newKMS(t)
		rec3Key := createKey(t, rec3KMS)

		require.NoError(t, err)

		sendPacker := newWithKMSAndCrypto(t, testingKMS)
		rec2Packer := newWithKMSAndCrypto(t, rec2KMS)

		msgIn := []byte("Junky qoph-flags vext crwd zimb.")

		var (
			enc []byte
			env *transport.Envelope
		)

		enc, err = sendPacker.Pack("", msgIn, []byte{}, [][]byte{rec1Key, rec2Key, rec3Key})
		require.NoError(t, err)
		env, err = rec2Packer.Unpack(enc)
		require.NoError(t, err)
		require.ElementsMatch(t, msgIn, env.Message)
		require.Equal(t, rec2Key, env.ToKey)

		emptyKMS, _ := newKMS(t)
		rec4Packer := newWithKMSAndCrypto(t, emptyKMS)

		_, err = rec4Packer.Unpack(enc)
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})

	t.Run("Test unpacking envelope", func(t *testing.T) {
		env := `{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQW5vbmNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6IjN3eFg1UUYybmVuYzUwUlRmSG10TmpQcVdieVhsOURseXhvRHlOYWx2a3U4MUhQdDVGanNrS3JpR1A1dE9FaHhYNmNyT3E2bjcxZXJRMU5zdWhGcm43VXVTUll3anRucmt1bmFaMjNaOWxZPSIsImhlYWRlciI6eyJraWQiOiI0U1B0ckRIMVpIOFpzaDZ1cGJVRzNUYmdYalliVzFDRUJSbk5ZNmlNdWRYOSJ9fV19","iv":"_Bp1NvfmNZ5Qe3iH","ciphertext":"eyETwK9I4NNPyitd","tag":"M8tMmORU7k11SvB_vStMpA=="}` // nolint: lll
		msg := "Hello World!"

		recPub := "4SPtrDH1ZH8Zsh6upbUG3TbgXjYbW1CEBRnNY6iMudX9"
		recPriv := "5MF9crszXCvzh9tWUWQwAuydh6tY2J5ErsaebwRzTsbNXx74mfaJXaKq7oTkoN4VMc2RtKktjMpPoU7vti9UnrdZ"

		recKMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, recPub, recPriv, recKMS))

		recPacker := newWithKMSAndCrypto(t, recKMS)

		var envOut *transport.Envelope
		envOut, err = recPacker.Unpack([]byte(env))
		require.NoError(t, err)
		require.ElementsMatch(t, []byte(msg), envOut.Message)
		require.Empty(t, envOut.FromKey)
		require.NotEmpty(t, envOut.ToKey)
		require.Equal(t, recPub, base58.Encode(envOut.ToKey))
	})

	t.Run("Test unpacking envelope with multiple recipients", func(t *testing.T) {
		env := `{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQW5vbmNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6ImZDMzgxN05OUWVCSTBtODNGOVlwbXdCWE5VNlRkX2V5WWdfSHI1WW41Z1ZlclliZmlHUXFTdGlZVmRBSUc4RlgwclJKd1c3SVBtYUcyTDY3dmQwSXZwWFowQ2sydjlfSldDbjNjSWkwa3Y0PSIsImhlYWRlciI6eyJraWQiOiJGN21OdEYyZnJMdVJ1MmNNRWpYQm5XZFljVFpBWE5QOWpFa3ByWHhpYVppMSJ9fSx7ImVuY3J5cHRlZF9rZXkiOiJKTjdaN3ZhOHc0T05iQkVnczI1bTdYbVFRM2NqTGo0WkZrRzBSOVc5SndVX1RsV3g5Q1pvb3lrZDZ4SWZBZk1tNVJjTjZIaGZKdEg5enpiVlVuVTlObF8wck9MVm96WEVIUGF1R2Vkc25uOD0iLCJoZWFkZXIiOnsia2lkIjoiQVE5bkh0TG5tdUc4MXB5NjRZRzVnZUYydmQ1aFFDS0hpNU1ycVExTFlDWEUifX1dfQ==","iv":"s5LdqRVlm23pxhxq","ciphertext":"HiMHFMlk6nwg7F6Q","tag":"tqPiHBpA2h4TeZFB9wNnyw=="}` // nolint: lll
		msg := "Hello World!"

		rec1Pub := "F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"
		rec1Priv := "2nYsWTQ1ZguQ7G2HYfMWjMNqWagBQfaKB9GLbsFk7Z7tKVBEr2arwpVKDwgLUbaxguUzQuf7o67aWKzgtHmKaypM"

		rec2Pub := "AQ9nHtLnmuG81py64YG5geF2vd5hQCKHi5MrqQ1LYCXE"
		rec2Priv := "2YbSVZzSVaim41bWDdsBzamrhXrPFKKEpzXZRmgDuoFJco5VQELRSj1oWFR9aRdaufsdUyw8sozTtZuX8Mzsqboz"

		rec1KMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, rec1Pub, rec1Priv, rec1KMS))

		rec2KMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, rec2Pub, rec2Priv, rec2KMS))

		rec1Packer := newWithKMSAndCrypto(t, rec1KMS)
		rec2Packer := newWithKMSAndCrypto(t, rec2KMS)

		var envOut *transport.Envelope
		envOut, err = rec1Packer.Unpack([]byte(env))
		require.NoError(t, err)
		require.ElementsMatch(t, []byte(msg), envOut.Message)
		require.Empty(t, envOut.FromKey)
		require.NotEmpty(t, envOut.ToKey)
		require.Equal(t, rec1Pub, base58.Encode(envOut.ToKey))

		envOut, err = rec2Packer.Unpack([]byte(env))
		require.NoError(t, err)
		require.ElementsMatch(t, []byte(msg), envOut.Message)
		require.Empty(t, envOut.FromKey)
		require.NotEmpty(t, envOut.ToKey)
		require.Equal(t, rec2Pub, base58.Encode(envOut.ToKey))
	})

	t.Run("Test unpacking envelope with invalid recipient", func(t *testing.T) {
		env := `{"protected":"eyJlbmMiOiJjaGFjaGEyMHBvbHkxMzA1X2lldGYiLCJ0eXAiOiJKV00vMS4wIiwiYWxnIjoiQW5vbmNyeXB0IiwicmVjaXBpZW50cyI6W3siZW5jcnlwdGVkX2tleSI6IkgwY09vVk5pT3FybTZPUFR1YzJ4cnBYaTRrTm1kSnhZV3haOE1iRWVOU0pYMENkR3EzaWRpQmtibjVYSDBTWjBtNEpfa0NYUFJaYVNqYjhLMVB3X0s5NnYzTFBjVzVPWjhWVkNKYkhHRUU0PSIsImhlYWRlciI6eyJraWQiOiJGN21OdEYyZnJMdVJ1MmNNRWpYQm5XZFljVFpBWE5QOWpFa3ByWHhpYVppMSJ9fV19","iv":"6cVlG23Fhy9oXB2h","ciphertext":"8vMl1QjgbCHreGCe","tag":"-VYChuk4kmnTk8Kz0Kz3Pg=="}` // nolint: lll

		recPub := "A3KnccxQu27yWQrSLwA2YFbfoSs4CHo3q6LjvhmpKz9h"
		recPriv := "49Y63zwonNoj2jEhMYE22TDwQCn7RLKMqNeSkSoBBucbAWceJuXXNCACXfpbXD7PHKM13SWaySyDukEakPVn5sWs"

		recKMS, _ := newKMS(t)
		require.NoError(t, persistKey(t, recPub, recPriv, recKMS))

		recPacker := newWithKMSAndCrypto(t, recKMS)

		_, err = recPacker.Unpack([]byte(env))
		require.NotNil(t, err)
		require.Contains(t, err.Error(), "no key accessible")
	})
}

func unpackComponentFailureTest(t *testing.T, protectedHeader, msg, recKeyPub, recKeyPriv, errString string) {
	t.Helper()

	fullMessage := `{"protected": "` + base64.URLEncoding.EncodeToString([]byte(protectedHeader)) + "\", " + msg

	w, _ := newKMS(t)

	err := persistKey(t, recKeyPub, recKeyPriv, w)

	if errString == "createKID: empty key" {
		require.EqualError(t, err, errString)
		return
	}

	require.NoError(t, err)

	recPacker := newWithKMSAndCrypto(t, w)
	_, err = recPacker.Unpack([]byte(fullMessage))
	require.NotNil(t, err)
	require.Contains(t, err.Error(), errString)
}

func TestUnpackComponents(t *testing.T) {
	recKeyPub := "F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"
	recKeyPriv := "2nYsWTQ1ZguQ7G2HYfMWjMNqWagBQfaKB9GLbsFk7Z7tKVBEr2arwpVKDwgLUbaxguUzQuf7o67aWKzgtHmKaypM"

	t.Run("Fail: non-JSON envelope", func(t *testing.T) {
		msg := `ed": "eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEu"}`

		w, _ := newKMS(t)
		require.NoError(t, persistKey(t, recKeyPub, recKeyPriv, w))

		recPacker := newWithKMSAndCrypto(t, w)

		_, err := recPacker.Unpack([]byte(msg))
		require.EqualError(t, err, "invalid character 'e' looking for beginning of value")
	})

	t.Run("Fail: non-base64 protected header", func(t *testing.T) {
		msg := `{"protected":"&**^(&^%","iv":"6cVlG23Fhy9oXB2h","ciphertext":"8vMl1QjgbCHreGCe","tag":"-VYChuk4kmnTk8Kz0Kz3Pg=="}` // nolint: lll

		w, _ := newKMS(t)
		require.NoError(t, persistKey(t, recKeyPub, recKeyPriv, w))

		recPacker := newWithKMSAndCrypto(t, w)

		_, err := recPacker.Unpack([]byte(msg))
		require.EqualError(t, err, "illegal base64 data at input byte 0")
	})

	t.Run("Fail: header not json", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`}eyJlbmMiOiAieGNoYWNoYTIwcG9seTEzMDVfaWV0ZiIsICJ0eXAiOiAiSldNLzEuMC`,
			`"not important":[]}`,
			recKeyPub, recKeyPriv,
			"invalid character '}' looking for beginning of value")
	})

	t.Run("Fail: bad 'typ' field", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JSON","alg":"Anoncrypt","recipients":[{"encrypted_key":"H0cOoVNiOqrm6OPTuc2xrpXi4kNmdJxYWxZ8MbEeNSJX0CdGq3idiBkbn5XH0SZ0m4J_kCXPRZaSjb8K1Pw_K96v3LPcW5OZ8VVCJbHGEE4=","header":{"kid":"F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                 // nolint: lll
			recKeyPub, recKeyPriv,
			"message type JSON not supported")
	})

	t.Run("Fail: authcrypt not supported", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Authcrypt","recipients":[{"encrypted_key":"H0cOoVNiOqrm6OPTuc2xrpXi4kNmdJxYWxZ8MbEeNSJX0CdGq3idiBkbn5XH0SZ0m4J_kCXPRZaSjb8K1Pw_K96v3LPcW5OZ8VVCJbHGEE4=","header":{"kid":"F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                    // nolint: lll
			recKeyPub, recKeyPriv,
			"message format Authcrypt not supported")
	})

	t.Run("Fail: no recipients in header", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc": "xchacha20poly1305_ietf", "typ": "JWM/1.0", "alg": "Anoncrypt", "recipients": []}`,
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			recKeyPub, recKeyPriv,
			"no key accessible")
	})

	t.Run("Fail: invalid public key", func(t *testing.T) {
		recPub := "6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7" // invalid key, won't convert

		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Anoncrypt","recipients":[{"encrypted_key":"H0cOoVNiOqrm6OPTuc2xrpXi4kNmdJxYWxZ8MbEeNSJX0CdGq3idiBkbn5XH0SZ0m4J_kCXPRZaSjb8K1Pw_K96v3LPcW5OZ8VVCJbHGEE4=","header":{"kid":"6ZAQ7QpmR9EqhJdwx1jQsjq6nnpehwVqUbhVxiEiYEV7"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                    // nolint: lll
			recPub, recKeyPriv,
			"sealOpen: failed to convert pub Ed25519 to X25519 key: error converting public key")
	})

	t.Run("Fail: invalid public key", func(t *testing.T) {
		recPub := "57N4aoQKaxUGNeEn3ETnTKgeD1L5Wm3U3Vb8qi3hupLn" // mismatched keypair, won't decrypt

		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Anoncrypt","recipients":[{"encrypted_key":"H0cOoVNiOqrm6OPTuc2xrpXi4kNmdJxYWxZ8MbEeNSJX0CdGq3idiBkbn5XH0SZ0m4J_kCXPRZaSjb8K1Pw_K96v3LPcW5OZ8VVCJbHGEE4=","header":{"kid":"57N4aoQKaxUGNeEn3ETnTKgeD1L5Wm3U3Vb8qi3hupLn"}}]}`, // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`,                                    // nolint: lll
			recPub, recKeyPriv,
			"failed to unpack")
	})

	t.Run("Encrypted CEK is invalid base64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Anoncrypt","recipients":[{"encrypted_key":"-","header":{"kid":"F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"}}]}`,                                                                         // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			recKeyPub, recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Bad encrypted key cannot be decrypted", func(t *testing.T) {
		unpackComponentFailureTest(t,
			`{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Anoncrypt","recipients":[{"encrypted_key":"H0cOoVNi","header":{"kid":"F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"}}]}`,                                                                  // nolint: lll
			`"iv": "oDZpVO648Po3UcoW", "ciphertext": "pLrFQ6dND0aB4saHjSklcNTDAvpFPmIvebCis7S6UupzhhPOHwhp6o97_EphsWbwqqHl0HTiT7W9kUqrvd8jcWgx5EATtkx5o3PSyHfsfm9jl0tmKsqu6VG0RML_OokZiFv76ZUZuGMrHKxkCHGytILhlpSwajg=", "tag": "6GigdWnW59aC9Y8jhy76rA=="}`, // nolint: lll
			recKeyPub, recKeyPriv,
			"failed to decrypt CEK")
	})

	// valid protected header for envelope being used
	prot := `{"enc":"chacha20poly1305_ietf","typ":"JWM/1.0","alg":"Anoncrypt","recipients":[{"encrypted_key":"H0cOoVNiOqrm6OPTuc2xrpXi4kNmdJxYWxZ8MbEeNSJX0CdGq3idiBkbn5XH0SZ0m4J_kCXPRZaSjb8K1Pw_K96v3LPcW5OZ8VVCJbHGEE4=","header":{"kid":"F7mNtF2frLuRu2cMEjXBnWdYcTZAXNP9jEkprXxiaZi1"}}]}` // nolint: lll

	t.Run("Ciphertext nonce not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv":"!!!","ciphertext":"8vMl1QjgbCHreGCe","tag":"-VYChuk4kmnTk8Kz0Kz3Pg=="}`,
			recKeyPub, recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Ciphertext not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot, `"iv":"6cVlG23Fhy9oXB2h","ciphertext":"-","tag":"-VYChuk4kmnTk8Kz0Kz3Pg=="}`,
			recKeyPub, recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	t.Run("Ciphertext tag not valid b64 data", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv":"6cVlG23Fhy9oXB2h","ciphertext":"8vMl1QjgbCHreGCe","tag":"-"}`,
			recKeyPub, recKeyPriv,
			"illegal base64 data at input byte 0")
	})

	badKeyPriv := "badkeyabcdefghijklmnopqrstuvwxyzbadkeyabcdefghijklmnopqrstuvwxyz"
	badKeyPub := "badkeyabcdefghijklmnopqrstuvwxyz"

	t.Run("Recipient Key not valid key", func(t *testing.T) {
		unpackComponentFailureTest(t,
			prot,
			`"iv":"6cVlG23Fhy9oXB2h","ciphertext":"8vMl1QjgbCHreGCe","tag":"-VYChuk4kmnTk8Kz0Kz3Pg=="}`,
			badKeyPub, badKeyPriv,
			"createKID: empty key")
	})
}

func Test_getCEK(t *testing.T) {
	k := mockkms.KeyManager{
		GetKeyValue: nil,
		GetKeyErr:   fmt.Errorf("mock error"),
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
	require.EqualError(t, err, "getCEK: no key accessible none of the recipient keys were found in kms: "+
		"[mock error]")
}

func Test_newCryptoBox(t *testing.T) {
	_, err := newCryptoBox(&mockkms.KeyManager{})
	require.EqualError(t, err, "cannot use parameter argument as KMS")

	_, err = newCryptoBox(&webkms.RemoteKMS{})
	require.NoError(t, err)
}
