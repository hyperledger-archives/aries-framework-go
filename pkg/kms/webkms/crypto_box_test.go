/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	mockkms "github.com/hyperledger/aries-framework-go/pkg/mock/kms"
)

func TestNewRemoteCryptoBox(t *testing.T) {
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	t.Run("create new cryptoBox with non remote kms implementation", func(t *testing.T) {
		_, err := NewCryptoBox(&mockkms.KeyManager{})
		require.EqualError(t, err, "cannot use parameter argument as KMS")
	})

	remoteKMS := New(defaultKeystoreURL, client)

	_, err := NewCryptoBox(remoteKMS)
	require.NoError(t, err)
}

func TestSealAndSealOpen(t *testing.T) {
	recPubKey, recPrivKey, err := ed25519.GenerateKey(rand.Reader)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTSealOpenRequest(w, r, recPubKey, recPrivKey)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	rKMS := New(defaultKeystoreURL, client)

	cryptoBox, err := NewCryptoBox(rKMS)
	require.NoError(t, err)

	payload := []byte("loremipsum")
	recEncPub, err := cryptoutil.PublicEd25519toCurve25519(recPubKey)
	require.NoError(t, err)

	cipherText, err := cryptoBox.Seal(payload, recEncPub, rand.Reader)
	require.NoError(t, err)

	decPayload, err := cryptoBox.SealOpen(cipherText, recPubKey)
	require.NoError(t, err)
	require.EqualValues(t, payload, decPayload)

	t.Run("SealOpen Post fail", func(t *testing.T) {
		blankClient := &http.Client{}
		rKMS1 := New(defaultKeystoreURL, blankClient)

		cBox, e := NewCryptoBox(rKMS1)
		require.NoError(t, e)

		_, e = cBox.SealOpen([]byte("mock cipherText"), recPubKey)
		require.Contains(t, e.Error(), "posting SealOpen failed ")
	})

	t.Run("SealOpen API error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		tmpKMS := New(_url, _client)

		var cBox *CryptoBox
		cBox, err = NewCryptoBox(tmpKMS)
		require.NoError(t, err)

		_, err = cBox.SealOpen([]byte("mock cipherText"), recPubKey)
		require.Contains(t, err.Error(), "api error msg")
	})

	t.Run("SealOpen fail to Marshal/UnMarshal", func(t *testing.T) {
		rKMS.marshalFunc = failingMarshal
		_, err = cryptoBox.SealOpen(cipherText, recPubKey)
		require.Contains(t, err.Error(), "failed to marshal SealOpen request")
		require.Contains(t, err.Error(), errFailingMarshal.Error())

		rKMS.marshalFunc = json.Marshal
		rKMS.unmarshalFunc = failingUnmarshal
		_, err = cryptoBox.SealOpen(cipherText, recPubKey)
		require.Contains(t, err.Error(), "unmarshal plaintext for SealOpen failed")
		require.Contains(t, err.Error(), errFailingUnmarshal.Error())
	})
}

// nolint:gocyclo // test code
func processPOSTSealOpenRequest(w http.ResponseWriter, r *http.Request, recipientPubKey ed25519.PublicKey,
	recipientPrivKey ed25519.PrivateKey) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	destination := "https://" + r.Host + r.URL.Path

	// nolint:nestif // test code
	if strings.LastIndex(r.URL.Path, sealOpenURL) == len(r.URL.Path)-len(sealOpenURL) {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read ciphertext request for SealOpen failed [%s, %w]", destination, err)
		}

		defer closeResponseBody(r.Body, logger, "MockServer-SealOpen")

		httpReq := &sealOpenReq{}

		err = json.Unmarshal(reqBody, httpReq)
		if err != nil {
			return fmt.Errorf("unmarshal SealOpen failed [%s, %w]", destination, err)
		}

		pkBytes := make([]byte, ed25519.PrivateKeySize)
		copy(pkBytes, recipientPrivKey)

		recipientEncPriv, err := cryptoutil.SecretEd25519toCurve25519(pkBytes)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 to Curve25519 private key for SealOpen [%s, %w]",
				destination, err)
		}

		cipherText := httpReq.Ciphertext

		var (
			epk  [cryptoutil.Curve25519KeySize]byte
			priv [cryptoutil.Curve25519KeySize]byte
		)

		copy(epk[:], cipherText[:cryptoutil.Curve25519KeySize])
		copy(priv[:], recipientEncPriv)

		recEncPub, err := cryptoutil.PublicEd25519toCurve25519(recipientPubKey)
		if err != nil {
			return fmt.Errorf("sealOpen: failed to convert pub Ed25519 to X25519 key: %w", err)
		}

		nonce, err := cryptoutil.Nonce(epk[:], recEncPub)
		if err != nil {
			return err
		}

		out, success := box.Open(nil, cipherText[cryptoutil.Curve25519KeySize:], nonce, &epk, &priv)
		if !success {
			return errors.New("failed to unpack")
		}

		resp := &sealOpenResp{
			Plaintext: out,
		}

		mResp, err := json.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(mResp)
		if err != nil {
			return err
		}
	}

	return nil
}

func TestEasyAndEasyOpen(t *testing.T) {
	recPubKey, recPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	senderPubKey, senderPrivKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTEasyOpenRequest(w, r, recPrivKey, senderPrivKey)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	rKMS := New(defaultKeystoreURL, client)

	cryptoBox, err := NewCryptoBox(rKMS)
	require.NoError(t, err)

	payload := []byte("loremipsum")
	nonce := random.GetRandomBytes(uint32(cryptoutil.NonceSize))

	recEncPub, err := cryptoutil.PublicEd25519toCurve25519(recPubKey)
	require.NoError(t, err)

	cipherText, err := cryptoBox.Easy(payload, nonce, recEncPub, defaultKID)
	require.NoError(t, err)

	senderEncPub, err := cryptoutil.PublicEd25519toCurve25519(senderPubKey)
	require.NoError(t, err)

	decPayload, err := cryptoBox.EasyOpen(cipherText, nonce, senderEncPub, recPubKey)
	require.NoError(t, err)
	require.EqualValues(t, payload, decPayload)

	t.Run("Easy/EasyOpen Post fail", func(t *testing.T) {
		blankClient := &http.Client{}
		rKMS1 := New(defaultKeystoreURL, blankClient)

		cBox, e := NewCryptoBox(rKMS1)
		require.NoError(t, e)

		_, e = cBox.Easy(payload, nonce, recEncPub, defaultKID)
		require.Contains(t, e.Error(), "posting Easy request failed ")

		_, e = cBox.EasyOpen([]byte("mock cipherText"), []byte("mock nonce"), senderEncPub, recPubKey)
		require.Contains(t, e.Error(), "posting EasyOpen failed ")
	})

	t.Run("Easy/EasyOpen API error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		tmpKMS := New(_url, _client)

		var cBox *CryptoBox
		cBox, err = NewCryptoBox(tmpKMS)
		require.NoError(t, err)

		_, err = cBox.Easy(payload, nonce, recEncPub, defaultKID)
		require.Contains(t, err.Error(), "api error msg")

		_, err = cBox.EasyOpen(cipherText, nonce, senderEncPub, recPubKey)
		require.Contains(t, err.Error(), "api error msg")
	})

	t.Run("Easy/EasyOpen fail to Marshal/UnMarshal", func(t *testing.T) {
		rKMS.marshalFunc = failingMarshal
		_, err = cryptoBox.Easy(payload, nonce, recEncPub, defaultKID)
		require.Contains(t, err.Error(), "failed to marshal Easy request")
		require.Contains(t, err.Error(), errFailingMarshal.Error())

		_, err = cryptoBox.EasyOpen([]byte("mock cipherText"), []byte("mock nonce"), senderEncPub, recPubKey)
		require.Contains(t, err.Error(), "failed to marshal EasyOpen request")
		require.Contains(t, err.Error(), errFailingMarshal.Error())

		rKMS.marshalFunc = json.Marshal
		rKMS.unmarshalFunc = failingUnmarshal
		_, err = cryptoBox.Easy(payload, nonce, recEncPub, defaultKID)
		require.Contains(t, err.Error(), "unmarshal ciphertext for Easy failed")
		require.Contains(t, err.Error(), errFailingUnmarshal.Error())

		_, err = cryptoBox.EasyOpen(cipherText, nonce, senderEncPub, recPubKey)
		require.Contains(t, err.Error(), "unmarshal plaintext for EasyOpen failed")
		require.Contains(t, err.Error(), errFailingUnmarshal.Error())
	})
}

// nolint:gocyclo // test code
func processPOSTEasyOpenRequest(w http.ResponseWriter, r *http.Request, recPrivKey, sPrivKey ed25519.PrivateKey) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	destination := "https://" + r.Host + r.URL.Path

	// nolint:nestif // test code
	if strings.LastIndex(r.URL.Path, easyURL) == len(r.URL.Path)-len(easyURL) {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read ciphertext request for EasyOpen failed [%s, %w]", destination, err)
		}

		defer closeResponseBody(r.Body, logger, "MockServer-Easy")

		httpReq := &easyReq{}

		err = json.Unmarshal(reqBody, httpReq)
		if err != nil {
			return fmt.Errorf("unmarshal EasyOpen failed [%s, %w]", destination, err)
		}

		payload := httpReq.Payload
		nonceReq := httpReq.Nonce
		recEncPub := httpReq.TheirPub

		var (
			recPubBytes [cryptoutil.Curve25519KeySize]byte
			priv        [cryptoutil.Curve25519KeySize]byte
			nonceBytes  [cryptoutil.NonceSize]byte
		)

		senderEncPriv, err := cryptoutil.SecretEd25519toCurve25519(sPrivKey)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 to Curve25519 private key for Easy [%s, %w]",
				destination, err)
		}

		copy(priv[:], senderEncPriv)
		copy(recPubBytes[:], recEncPub)
		copy(nonceBytes[:], nonceReq)

		out := box.Seal(nil, payload, &nonceBytes, &recPubBytes, &priv)

		resp := &easyResp{
			Ciphertext: out,
		}

		mResp, err := json.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(mResp)
		if err != nil {
			return err
		}
	}

	// nolint:nestif // test code
	if strings.LastIndex(r.URL.Path, easyOpenURL) == len(r.URL.Path)-len(easyOpenURL) {
		reqBody, err := ioutil.ReadAll(r.Body)
		if err != nil {
			return fmt.Errorf("read ciphertext request for EasyOpen failed [%s, %w]", destination, err)
		}

		defer closeResponseBody(r.Body, logger, "MockServer-EasyOpen")

		httpReq := &easyOpenReq{}

		err = json.Unmarshal(reqBody, httpReq)
		if err != nil {
			return fmt.Errorf("unmarshal EasyOpen failed [%s, %w]", destination, err)
		}

		pkBytes := make([]byte, ed25519.PrivateKeySize)
		copy(pkBytes, recPrivKey)

		recipientEncPriv, err := cryptoutil.SecretEd25519toCurve25519(pkBytes)
		if err != nil {
			return fmt.Errorf("failed to convert Ed25519 to Curve25519 private key for EasyOpen [%s, %w]",
				destination, err)
		}

		cipherText := httpReq.Ciphertext
		senderPubKey := httpReq.TheirPub
		nonceReq := httpReq.Nonce

		var (
			senderPubKeyBytes [cryptoutil.Curve25519KeySize]byte
			priv              [cryptoutil.Curve25519KeySize]byte
			nonce             [cryptoutil.NonceSize]byte
		)

		copy(senderPubKeyBytes[:], senderPubKey)
		copy(priv[:], recipientEncPriv)
		copy(nonce[:], nonceReq)

		out, success := box.Open(nil, cipherText, &nonce, &senderPubKeyBytes, &priv)

		if !success {
			return errors.New("failed to unpack")
		}

		resp := &easyOpenResp{
			Plaintext: out,
		}

		mResp, err := json.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(mResp)
		if err != nil {
			return err
		}
	}

	return nil
}
