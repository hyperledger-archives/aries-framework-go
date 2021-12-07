/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/tink/go/aead"
	aeadsubtle "github.com/google/tink/go/aead/subtle"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/mac"
	"github.com/google/tink/go/signature"
	"github.com/google/tink/go/subtle/random"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/bbs"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	webkmsimpl "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
)

const (
	certPrefix        = "../../didcomm/transport/http/testdata/crypto/"
	clientTimeout     = 5 * time.Second
	defaultKeyStoreID = "12345"
	defaultKID        = "99999"
)

func TestEncryptDecrypt(t *testing.T) {
	kh, err := keyset.NewHandle(aead.XChaCha20Poly1305KeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTEncRequest(w, r, kh)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID
	rCrypto := New(defaultKeystoreURL, client)
	plaintext := []byte("lorem ipsum")
	aad := []byte("dolor sit")

	// test successful Encrypt/Decrypt
	ciphertext, nonce, err := rCrypto.Encrypt(plaintext, aad, defaultKeyURL)
	require.NoError(t, err)

	decrypted, err := rCrypto.Decrypt(ciphertext, aad, nonce, defaultKeyURL)
	require.NoError(t, err)
	require.EqualValues(t, plaintext, decrypted)

	t.Run("Encrypt Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, _, err = tmpCrypto.Encrypt(plaintext, aad, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting Encrypt plaintext failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+encryptURI, defaultKeyURL+encryptURI))

		badURL := "``#$%"
		_, _, err = tmpCrypto.Encrypt(plaintext, aad, badURL)
		require.Contains(t, err.Error(), "posting Encrypt plaintext failed")
		require.EqualError(t, err, fmt.Errorf("posting Encrypt plaintext failed [%s, build request error:"+
			" parse \"%s\": invalid URL escape \"%s\"]", badURL+encryptURI, badURL+encryptURI, "%/e").Error())
	})

	t.Run("Decrypt Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.Decrypt(nil, aad, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting Decrypt ciphertext failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+decryptURI, defaultKeyURL+decryptURI))
	})

	t.Run("Encrypt json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, _, err = remoteCrypto2.Encrypt(plaintext, aad, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal encryption request for Encrypt failed [%s, %w]",
			defaultKeyURL+encryptURI, errFailingMarshal).Error())
	})

	t.Run("Encrypt json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, _, err = remoteCrypto2.Encrypt(plaintext, aad, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal encryption for Encrypt failed [%s, %w]",
			defaultKeyURL+encryptURI, errFailingUnmarshal).Error())
	})

	t.Run("Decrypt json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.Decrypt(ciphertext, aad, nonce, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal decryption request for Decrypt failed [%s, %w]",
			defaultKeyURL+decryptURI, errFailingMarshal).Error())
	})

	t.Run("Decrypt json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.Decrypt(ciphertext, aad, nonce, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal decryption for Decrypt failed [%s, %w]",
			defaultKeyURL+decryptURI, errFailingUnmarshal).Error())
	})
}

func processPOSTEncRequest(w http.ResponseWriter, r *http.Request, encKH *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, encryptURI) == len(r.URL.Path)-len(encryptURI) {
		err = encryptPOSTHandle(w, reqBody, encKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, decryptURI) == len(r.URL.Path)-len(decryptURI) {
		err = decryptPOSTHandle(w, reqBody, encKH)
		if err != nil {
			return err
		}
	}

	return nil
}

func encryptPOSTHandle(w http.ResponseWriter, reqBody []byte, encKH *keyset.Handle) error {
	encReq := &encryptReq{}

	err := json.Unmarshal(reqBody, encReq)
	if err != nil {
		return err
	}

	ps, err := encKH.Primitives()
	if err != nil {
		return err
	}

	a, err := aead.New(encKH)
	if err != nil {
		return err
	}

	ct, err := a.Encrypt(encReq.Message, encReq.AssociatedData)
	if err != nil {
		return fmt.Errorf("encrypt msg: %w", err)
	}

	ivSize := nonceSize(ps)
	prefixLength := len(ps.Primary.Prefix)
	cipherText := ct[prefixLength+ivSize:]
	nonce := ct[prefixLength : prefixLength+ivSize]

	resp := &encryptResp{
		Ciphertext: cipherText,
		Nonce:      nonce,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func decryptPOSTHandle(w http.ResponseWriter, reqBody []byte, encKH *keyset.Handle) error {
	decReq := &decryptReq{}

	err := json.Unmarshal(reqBody, decReq)
	if err != nil {
		return err
	}

	ps, err := encKH.Primitives()
	if err != nil {
		return err
	}

	a, err := aead.New(encKH)
	if err != nil {
		return err
	}

	cipher := decReq.Ciphertext
	nonce := decReq.Nonce

	ct := make([]byte, 0, len(ps.Primary.Prefix)+len(nonce)+len(cipher))
	ct = append(ct, ps.Primary.Prefix...)
	ct = append(ct, nonce...)
	ct = append(ct, cipher...)

	plaintext, err := a.Decrypt(ct, decReq.AssociatedData)
	if err != nil {
		return fmt.Errorf("decrypt cipher: %w", err)
	}

	resp := &decryptResp{
		Plaintext: plaintext,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func TestSignVerify(t *testing.T) {
	kh, err := keyset.NewHandle(signature.ECDSAP384KeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTSigRequest(w, r, kh)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID
	rCrypto := New(defaultKeystoreURL, client)
	msg := []byte("lorem ipsum")

	// test successful Sign/Verify
	sig, err := rCrypto.Sign(msg, defaultKeyURL)
	require.NoError(t, err)

	err = rCrypto.Verify(sig, msg, defaultKeyURL)
	require.NoError(t, err)

	t.Run("Sign Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.Sign(nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting Sign message failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+signURI, defaultKeyURL+signURI))
	})

	t.Run("Verify Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		err = tmpCrypto.Verify(nil, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting Verify signature failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+verifyURI, defaultKeyURL+verifyURI))
	})

	t.Run("Sign json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.Sign(msg, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal signature request for Sign failed [%s, %w]",
			defaultKeyURL+signURI, errFailingMarshal).Error())
	})

	t.Run("Sign json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.Sign(msg, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal signature for Sign failed [%s, %w]",
			defaultKeyURL+signURI, errFailingUnmarshal).Error())
	})

	t.Run("Verify json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		err = remoteCrypto2.Verify(sig, msg, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal verify request for Verify failed [%s, %w]",
			defaultKeyURL+verifyURI, errFailingMarshal).Error())
	})
}

func processPOSTSigRequest(w http.ResponseWriter, r *http.Request, sigKH *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, signURI) == len(r.URL.Path)-len(signURI) {
		err = signPOSTHandle(w, reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, verifyURI) == len(r.URL.Path)-len(verifyURI) {
		err = verifyPOSTHandle(reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	return nil
}

func signPOSTHandle(w http.ResponseWriter, reqBody []byte, sigKH *keyset.Handle) error {
	sigReq := &signReq{}

	err := json.Unmarshal(reqBody, sigReq)
	if err != nil {
		return err
	}

	signer, err := signature.NewSigner(sigKH)
	if err != nil {
		return fmt.Errorf("create new signer: %w", err)
	}

	s, err := signer.Sign(sigReq.Message)
	if err != nil {
		return fmt.Errorf("sign msg: %w", err)
	}

	resp := &signResp{
		Signature: s,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func verifyPOSTHandle(reqBody []byte, sigKH *keyset.Handle) error {
	verReq := &verifyReq{}

	err := json.Unmarshal(reqBody, verReq)
	if err != nil {
		return err
	}

	pubKH, err := sigKH.Public()
	if err != nil {
		return err
	}

	verifier, err := signature.NewVerifier(pubKH)
	if err != nil {
		return fmt.Errorf("create new verifier: %w", err)
	}

	err = verifier.Verify(verReq.Signature, verReq.Message)
	if err != nil {
		return fmt.Errorf("verify msg: %w", err)
	}

	return nil
}

func TestComputeVerifyMAC(t *testing.T) {
	kh, err := keyset.NewHandle(mac.HMACSHA256Tag256KeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTMACRequest(w, r, kh)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID
	rCrypto := New(defaultKeystoreURL, client, webkmsimpl.WithCache(2))
	data := []byte("lorem ipsum")

	// test successful ComputeMAC/VerifyMAC
	dataMAC, err := rCrypto.ComputeMAC(data, defaultKeyURL)
	require.NoError(t, err)

	err = rCrypto.VerifyMAC(dataMAC, data, defaultKeyURL)
	require.NoError(t, err)

	dataMAC, err = rCrypto.ComputeMAC(data, defaultKeyURL)
	require.NoError(t, err)

	err = rCrypto.VerifyMAC(dataMAC, data, defaultKeyURL)
	require.NoError(t, err)

	t.Run("ComputeMAC Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.ComputeMAC(nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting ComputeMAC request failed [%s, Post \"%s\": x509: certificate"+
			" signed by unknown authority", defaultKeyURL+computeMACURI, defaultKeyURL+computeMACURI))
	})

	t.Run("VerifyMAC Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		err = tmpCrypto.VerifyMAC(nil, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting VerifyMAC request failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+verifyMACURI, defaultKeyURL+verifyMACURI))
	})

	t.Run("ComputeMAC json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.ComputeMAC(data, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal request for ComputeMAC failed [%s, %w]",
			defaultKeyURL+computeMACURI, errFailingMarshal).Error())
	})

	t.Run("ComputeMAC json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.ComputeMAC(data, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal ComputeMAC response failed [%s, %w]",
			defaultKeyURL+computeMACURI, errFailingUnmarshal).Error())
	})

	t.Run("VerifyMAC json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		err = remoteCrypto2.VerifyMAC(dataMAC, data, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal request for VerifyMAC failed [%s, %w]",
			defaultKeyURL+verifyMACURI, errFailingMarshal).Error())
	})
}

func processPOSTMACRequest(w http.ResponseWriter, r *http.Request, macKH *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, computeMACURI) == len(r.URL.Path)-len(computeMACURI) {
		err = computeMACPOSTHandle(w, reqBody, macKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, verifyMACURI) == len(r.URL.Path)-len(verifyMACURI) {
		err = verifyMACPOSTHandle(reqBody, macKH)
		if err != nil {
			return err
		}
	}

	return nil
}

func computeMACPOSTHandle(w http.ResponseWriter, reqBody []byte, macKH *keyset.Handle) error {
	macReq := &computeMACReq{}

	err := json.Unmarshal(reqBody, macReq)
	if err != nil {
		return err
	}

	macPrimitive, err := mac.New(macKH)
	if err != nil {
		return err
	}

	dataMAC, err := macPrimitive.ComputeMAC(macReq.Data)
	if err != nil {
		return err
	}

	resp := &computeMACResp{
		MAC: dataMAC,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func verifyMACPOSTHandle(reqBody []byte, macKH *keyset.Handle) error {
	verReq := &verifyMACReq{}

	err := json.Unmarshal(reqBody, verReq)
	if err != nil {
		return err
	}

	macPrimitive, err := mac.New(macKH)
	if err != nil {
		return err
	}

	err = macPrimitive.VerifyMAC(verReq.MAC, verReq.Data)
	if err != nil {
		return fmt.Errorf("verify mac: %w", err)
	}

	return nil
}

func TestWrapUnWrapKey(t *testing.T) {
	senderKID := "11111"

	recipientKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipentPubKey, err := exportPubKey(recipientKH)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTWrapRequest(w, r, senderKH, recipientKH)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID
	rCrypto := New(defaultKeystoreURL, client)
	cek := random.GetRandomBytes(uint32(32))
	apu := []byte("bob")
	apv := []byte("alice")

	// Test successful WrapKey/UnwrapKey
	wKey, err := rCrypto.WrapKey(cek, apu, apv, recipentPubKey)
	require.NoError(t, err)

	decryptedCEK, err := rCrypto.UnwrapKey(wKey, defaultKeyURL)
	require.NoError(t, err)
	require.EqualValues(t, cek, decryptedCEK)

	t.Run("WrapKey Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.WrapKey(cek, apu, apv, recipentPubKey)
		require.Contains(t, err.Error(), fmt.Sprintf("posting WrapKey failed [%s, Post \"%s\": x509: certificate"+
			" signed by unknown authority", defaultKeystoreURL+wrapURI, defaultKeystoreURL+wrapURI))
	})

	t.Run("UnwrapKey Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.UnwrapKey(wKey, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting UnwrapKey failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+unwrapURI, defaultKeyURL+unwrapURI))
	})

	t.Run("WrapKey json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.WrapKey(cek, apu, apv, recipentPubKey)
		require.EqualError(t, err, fmt.Errorf("marshal wrapKeyReq for WrapKey failed [%s, %w]",
			defaultKeystoreURL+wrapURI, errFailingMarshal).Error())
	})

	t.Run("WrapKey json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.WrapKey(cek, apu, apv, recipentPubKey)
		require.EqualError(t, err, fmt.Errorf("unmarshal wrapKeyResp for WrapKey failed [%s, %w]",
			defaultKeystoreURL+wrapURI, errFailingUnmarshal).Error())
	})

	t.Run("UnwrapKey json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.UnwrapKey(wKey, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal unwrapKeyResp for UnwrapKey failed [%s, %w]",
			defaultKeyURL+unwrapURI, errFailingUnmarshal).Error())
	})

	t.Run("Unwrap json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.UnwrapKey(wKey, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal unwrapKeyReq for UnwrapKey failed [%s, %w]",
			defaultKeyURL+unwrapURI, errFailingMarshal).Error())
	})

	t.Run("Wrap/Unwrap successful with Sender key (authcrypt)", func(t *testing.T) {
		wrappedKey, err := rCrypto.WrapKey(cek, apu, apv, recipentPubKey, crypto.WithSender(senderKID))
		require.NoError(t, err)

		dCEK, err := rCrypto.UnwrapKey(wrappedKey, defaultKeyURL, crypto.WithSender(&crypto.PublicKey{}))
		require.NoError(t, err)
		require.EqualValues(t, cek, dCEK)
	})

	t.Run("Wrap/Unwrap with Sender key option containing empty key", func(t *testing.T) {
		wrappedKey, err := rCrypto.WrapKey(cek, apu, apv, recipentPubKey, crypto.WithSender(""))
		require.NoError(t, err)

		dCEK, err := rCrypto.UnwrapKey(wrappedKey, defaultKeyURL)
		require.NoError(t, err)
		require.EqualValues(t, cek, dCEK)
	})

	t.Run("Wrap/Unwrap with Sender key option containing nil key", func(t *testing.T) {
		wrappedKey, err := rCrypto.WrapKey(cek, apu, apv, recipentPubKey, crypto.WithSender(nil))
		require.NoError(t, err)

		dCEK, err := rCrypto.UnwrapKey(wrappedKey, defaultKeyURL, crypto.WithSender(nil))
		require.NoError(t, err)
		require.EqualValues(t, cek, dCEK)
	})
}

func TestRemoteCryptoWithHeadersFunc(t *testing.T) {
	recipientKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipentPubKey, err := exportPubKey(recipientKH)
	require.NoError(t, err)

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTWrapRequest(w, r, senderKH, recipientKH)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID

	t.Run("New remote crypto using WithHeaders with success function", func(t *testing.T) {
		rCrypto := New(defaultKeystoreURL, client, webkmsimpl.WithHeaders(mockAddHeadersFuncSuccess))
		cek := random.GetRandomBytes(uint32(32))
		apu := []byte("bob")
		apv := []byte("alice")

		// Test successful WrapKey/UnwrapKey
		wKey, e := rCrypto.WrapKey(cek, apu, apv, recipentPubKey)
		require.NoError(t, e)

		decryptedCEK, e := rCrypto.UnwrapKey(wKey, defaultKeyURL)
		require.NoError(t, e)
		require.EqualValues(t, cek, decryptedCEK)
	})

	t.Run("New remote crypto using WithHeaders with error function", func(t *testing.T) {
		rCrypto := New(defaultKeystoreURL, client, webkmsimpl.WithHeaders(mockAddHeadersFuncError))
		cek := random.GetRandomBytes(uint32(32))
		apu := []byte("bob")
		apv := []byte("alice")

		// Test successful WrapKey/UnwrapKey
		_, err = rCrypto.WrapKey(cek, apu, apv, recipentPubKey)
		require.EqualError(t, err, fmt.Errorf("posting WrapKey failed [%s%s, add optional request "+
			"headers error: %w]", defaultKeystoreURL, wrapURI, errAddHeadersFunc).Error())

		wKey := &crypto.RecipientWrappedKey{
			KID:          "1",
			EncryptedCEK: []byte("111"),
			EPK:          crypto.PublicKey{},
			Alg:          "zlg",
			APU:          []byte("bob"),
			APV:          []byte("Alice"),
		}

		_, err = rCrypto.UnwrapKey(wKey, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("posting UnwrapKey failed [%s%s, add optional request "+
			"headers error: %w]", defaultKeyURL, unwrapURI, errAddHeadersFunc).Error())
	})
}

func exportPubKey(kh *keyset.Handle) (*crypto.PublicKey, error) {
	pubKH, err := kh.Public()
	if err != nil {
		return nil, fmt.Errorf("exportPubKey: failed to get public keyset handle: %w", err)
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := localkms.NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, fmt.Errorf("exportPubKey: failed to create keyset with no secrets (public "+
			"key material): %w", err)
	}

	recPubKey := &crypto.PublicKey{}

	err = json.Unmarshal(buf.Bytes(), recPubKey)
	if err != nil {
		return nil, fmt.Errorf("exportPubKey: failed to unmarshal public key: %w", err)
	}

	return recPubKey, nil
}

func processPOSTWrapRequest(w http.ResponseWriter, r *http.Request, senderKH, recKH *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	cr, err := tinkcrypto.New()
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, wrapURI) == len(r.URL.Path)-len(wrapURI) {
		if strings.Contains(r.URL.Path, keysURI+"/") {
			// URL contains sender key id and has form "keystorepath/keys/{senderKeyId}/wrap"
			err = wrapKeyPostHandle(w, reqBody, senderKH, cr)
		} else {
			err = wrapKeyPostHandle(w, reqBody, nil, cr)
		}

		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, unwrapURI) == len(r.URL.Path)-len(unwrapURI) {
		err = unwrapKeyPostHandle(w, reqBody, senderKH, recKH, cr)
		if err != nil {
			return err
		}
	}

	return nil
}

func wrapKeyPostHandle(w http.ResponseWriter, reqBody []byte, senderKH *keyset.Handle, cr crypto.Crypto) error {
	wrapReq := &wrapKeyReq{}

	err := json.Unmarshal(reqBody, wrapReq)
	if err != nil {
		return err
	}

	wk, err := buildRecipientWK(wrapReq.CEK, wrapReq.APU, wrapReq.APV, senderKH, wrapReq, cr)
	if err != nil {
		return err
	}

	resp := &wrapKeyResp{
		RecipientWrappedKey: *wk,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func buildRecipientWK(cek, apu, apv []byte, senderKH *keyset.Handle, wrapReq *wrapKeyReq,
	cr crypto.Crypto) (*crypto.RecipientWrappedKey, error) {
	var (
		wk  *crypto.RecipientWrappedKey
		opt crypto.WrapKeyOpts
		err error
	)

	if senderKH != nil {
		opt = crypto.WithSender(senderKH)

		wk, err = cr.WrapKey(cek, apu, apv, wrapReq.RecipientPubKey, opt)
		if err != nil {
			return nil, err
		}
	} else {
		wk, err = cr.WrapKey(cek, apu, apv, wrapReq.RecipientPubKey)
		if err != nil {
			return nil, err
		}
	}

	return wk, nil
}

func unwrapKeyPostHandle(w http.ResponseWriter, reqBody []byte, senderKH, recKH *keyset.Handle,
	cr crypto.Crypto) error {
	unwrapReq := &unwrapKeyReq{}

	err := json.Unmarshal(reqBody, unwrapReq)
	if err != nil {
		return err
	}

	var opt crypto.WrapKeyOpts

	var cek []byte

	if unwrapReq.SenderPubKey != nil {
		opt = crypto.WithSender(senderKH)

		cek, err = cr.UnwrapKey(&unwrapReq.WrappedKey, recKH, opt)
		if err != nil {
			return err
		}
	} else {
		cek, err = cr.UnwrapKey(&unwrapReq.WrappedKey, recKH)
		if err != nil {
			return err
		}
	}

	resp := &unwrapKeyResp{
		Key: cek,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func TestBBSSignVerify_DeriveProofVerifyProof(t *testing.T) {
	kh, err := keyset.NewHandle(bbs.BLS12381G2KeyTemplate())
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processBBSPOSTRequest(w, r, kh)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	defaultKeyURL := defaultKeystoreURL + "/keys/" + defaultKID
	rCrypto := New(defaultKeystoreURL, client)
	msg := [][]byte{[]byte("lorem ipsum"), []byte("dolor sit amet,"), []byte("consectetur adipiscing elit,")}

	nonce := make([]byte, 32)

	_, err = rand.Read(nonce)
	require.NoError(t, err)

	// test successful BBS+ Sign/Verify/DeriveProof/VerifyProof
	sig, err := rCrypto.SignMulti(msg, defaultKeyURL)
	require.NoError(t, err)

	err = rCrypto.VerifyMulti(msg, sig, defaultKeyURL)
	require.NoError(t, err)

	proof, err := rCrypto.DeriveProof(msg, sig, nonce, []int{1, 2}, defaultKeyURL)
	require.NoError(t, err)

	err = rCrypto.VerifyProof([][]byte{msg[1], msg[2]}, proof, nonce, defaultKeyURL)
	require.NoError(t, err)

	t.Run("BBS+ Sign Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.SignMulti(nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting BBS+ Sign message failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+signMultiURI, defaultKeyURL+signMultiURI))
	})

	t.Run("BBS+ Verify Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		err = tmpCrypto.VerifyMulti(nil, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting BBS+ Verify signature failed [%s, Post \"%s\": x509: "+
			"certificate signed by unknown authority", defaultKeyURL+verifyMultiURI, defaultKeyURL+verifyMultiURI))
	})

	t.Run("BBS+ Derive Proof Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		_, err = tmpCrypto.DeriveProof(nil, nil, nil, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting BBS+ Derive proof message failed [%s, Post \"%s\": "+
			"x509: certificate signed by unknown authority", defaultKeyURL+deriveProofURI,
			defaultKeyURL+deriveProofURI))
	})

	t.Run("BBS+ Verify Proof Post request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		err = tmpCrypto.VerifyProof(nil, nil, nil, defaultKeyURL)
		require.Contains(t, err.Error(), fmt.Sprintf("posting BBS+ Verify proof failed [%s, Post \"%s\": "+
			"x509: certificate signed by unknown authority", defaultKeyURL+verifyProofURI,
			defaultKeyURL+verifyProofURI))
	})

	t.Run("BBS+ Sign json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.SignMulti(msg, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal signature request for BBS+ Sign failed [%s, %w]",
			defaultKeyURL+signMultiURI, errFailingMarshal).Error())
	})

	t.Run("BBS+ Sign json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.SignMulti(msg, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal signature for BBS+ Sign failed [%s, %w]",
			defaultKeyURL+signMultiURI, errFailingUnmarshal).Error())
	})

	t.Run("BBS+ Verify json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		err = remoteCrypto2.VerifyMulti(msg, sig, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal verify request for BBS+ Verify failed [%s, %w]",
			defaultKeyURL+verifyMultiURI, errFailingMarshal).Error())
	})

	t.Run("BBS+ Derive Proof json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		_, err = remoteCrypto2.DeriveProof(msg, sig, nonce, []int{0}, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal request for BBS+ Derive proof failed [%s, %w]",
			defaultKeyURL+deriveProofURI, errFailingMarshal).Error())
	})

	t.Run("BBS+ Derive Proof json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal
		_, err = remoteCrypto2.DeriveProof(msg, sig, nonce, []int{0}, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("unmarshal request for BBS+ Derive proof failed [%s, %w]",
			defaultKeyURL+deriveProofURI, errFailingUnmarshal).Error())
	})

	t.Run("BBS+ Verify Proof json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal
		err = remoteCrypto2.VerifyProof([][]byte{msg[1], msg[2]}, proof, nonce, defaultKeyURL)
		require.EqualError(t, err, fmt.Errorf("marshal request for BBS+ Verify proof failed [%s, %w]",
			defaultKeyURL+verifyProofURI, errFailingMarshal).Error())
	})
}

func TestNonOKStatusCode(t *testing.T) {
	aad := []byte("dolor sit")

	nonOKServer, nonOkURL, nonOKClient := CreateMockHTTPServerAndClientNotOKStatusCode(t)

	defer func() {
		e := nonOKServer.Close()
		require.NoError(t, e)
	}()

	nonOKDefaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", nonOkURL), defaultKeyStoreID)
	nonOKDefaultKeyURL := nonOKDefaultKeystoreURL + "/keys/" + defaultKID

	t.Run("Encrypt Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, _, err := tmpCrypto.Encrypt(nil, aad, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("Decrypt Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.Decrypt(nil, aad, nil, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("Sign Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.Sign([]byte("Test message"), nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("Verify Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		err := tmpCrypto.Verify([]byte{}, []byte("Test message"), nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("ComputeMAC Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.ComputeMAC([]byte("Test message"), nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("VerifyMAC Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		err := tmpCrypto.VerifyMAC([]byte{}, []byte("Test message"), nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("SignMulti Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.SignMulti([][]byte{
			[]byte("Test message 1"),
			[]byte("Test message 2"),
		}, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("VerifyMAC Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		err := tmpCrypto.VerifyMulti([][]byte{
			[]byte("Test message 1"),
			[]byte("Test message 2"),
		}, []byte{}, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("WrapKey Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.WrapKey([]byte{}, []byte{}, []byte{}, nil)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("UnwrapKey Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.UnwrapKey(&crypto.RecipientWrappedKey{}, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("DeriveProof Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		_, err := tmpCrypto.DeriveProof([][]byte{
			[]byte("Test message 1"),
			[]byte("Test message 2"),
		}, []byte{}, []byte{}, []int{}, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})

	t.Run("VerifyProof Post request failure 501", func(t *testing.T) {
		tmpCrypto := New(nonOKDefaultKeyURL, nonOKClient)

		err := tmpCrypto.VerifyProof([][]byte{
			[]byte("Test message 1"),
			[]byte("Test message 2"),
		}, []byte{}, []byte{}, nonOKDefaultKeyURL)
		require.Contains(t, err.Error(), "501")
	})
}

// nolint:gocyclo
func processBBSPOSTRequest(w http.ResponseWriter, r *http.Request, sigKH *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if strings.LastIndex(r.URL.Path, signMultiURI) == len(r.URL.Path)-len(signMultiURI) {
		err = bbsSignPOSTHandle(w, reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, verifyMultiURI) == len(r.URL.Path)-len(verifyMultiURI) {
		err = bbsVerifyPOSTHandle(reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, deriveProofURI) == len(r.URL.Path)-len(deriveProofURI) {
		err = bbsDeriveProofPOSTHandle(w, reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	if strings.LastIndex(r.URL.Path, verifyProofURI) == len(r.URL.Path)-len(verifyProofURI) {
		err = bbsVerifyProofPOSTHandle(reqBody, sigKH)
		if err != nil {
			return err
		}
	}

	return nil
}

func bbsSignPOSTHandle(w http.ResponseWriter, reqBody []byte, sigKH *keyset.Handle) error {
	sigReq := &signMultiReq{}

	err := json.Unmarshal(reqBody, sigReq)
	if err != nil {
		return err
	}

	signer, err := bbs.NewSigner(sigKH)
	if err != nil {
		return fmt.Errorf("create new signer: %w", err)
	}

	s, err := signer.Sign(sigReq.Messages)
	if err != nil {
		return fmt.Errorf("sign msg: %w", err)
	}

	resp := &signResp{
		Signature: s,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func bbsVerifyPOSTHandle(reqBody []byte, sigKH *keyset.Handle) error {
	verReq := &verifyMultiReq{}

	err := json.Unmarshal(reqBody, verReq)
	if err != nil {
		return err
	}

	pubKH, err := sigKH.Public()
	if err != nil {
		return err
	}

	verifier, err := bbs.NewVerifier(pubKH)
	if err != nil {
		return fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	err = verifier.Verify(verReq.Messages, verReq.Signature)
	if err != nil {
		return fmt.Errorf("BBS+ verify msg: %w", err)
	}

	return nil
}

func bbsDeriveProofPOSTHandle(w http.ResponseWriter, reqBody []byte, sigKH *keyset.Handle) error {
	deriveProofReq := &deriveProofReq{}

	err := json.Unmarshal(reqBody, deriveProofReq)
	if err != nil {
		return err
	}

	pubKH, err := sigKH.Public()
	if err != nil {
		return err
	}

	verifier, err := bbs.NewVerifier(pubKH)
	if err != nil {
		return fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	proof, err := verifier.DeriveProof(deriveProofReq.Messages,
		deriveProofReq.Signature,
		deriveProofReq.Nonce,
		deriveProofReq.RevealedIndexes)
	if err != nil {
		return fmt.Errorf("BBS+ derive proof msg: %w", err)
	}

	resp := &deriveProofResp{
		Proof: proof,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func bbsVerifyProofPOSTHandle(reqBody []byte, sigKH *keyset.Handle) error {
	verifyProofReq := &verifyProofReq{}

	err := json.Unmarshal(reqBody, verifyProofReq)
	if err != nil {
		return err
	}

	pubKH, err := sigKH.Public()
	if err != nil {
		return err
	}

	verifier, err := bbs.NewVerifier(pubKH)
	if err != nil {
		return fmt.Errorf("create new BBS+ verifier: %w", err)
	}

	err = verifier.VerifyProof(verifyProofReq.Messages, verifyProofReq.Proof, verifyProofReq.Nonce)
	if err != nil {
		return fmt.Errorf("BBS+ verify proof msg: %w", err)
	}

	return nil
}

func TestCloseResponseBody(t *testing.T) {
	closeResponseBody(&errFailingCloser{}, logger, "testing close fail should log: errFailingCloser always fails")
}

func nonceSize(ps *primitiveset.PrimitiveSet) int {
	var ivSize int
	// AES256GCM and XChacha20Poly1305 nonce sizes supported only for now
	switch ps.Primary.Primitive.(type) {
	case *aeadsubtle.XChaCha20Poly1305:
		ivSize = chacha20poly1305.NonceSizeX
	case *aeadsubtle.AESGCM:
		ivSize = aeadsubtle.AESGCMIVSize
	default:
		ivSize = aeadsubtle.AESGCMIVSize
	}

	return ivSize
}

// validateHTTPMethod validate HTTP method and content-type.
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodGet:
	default:
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != webkmsimpl.ContentType && r.Method == http.MethodPost {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

// validatePayload validate and get the payload from the request.
func validatePostPayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 && r.Method == http.MethodPost { // empty payload should not be accepted for POST request
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}

	return true
}

// CreateMockHTTPServerAndClient creates mock http server and client using tls and returns them.
func CreateMockHTTPServerAndClient(t *testing.T, inHandler http.Handler) (net.Listener, string, *http.Client) {
	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)

	// build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{ //nolint:gosec
		RootCAs:      cp,
		Certificates: nil,
	}

	// create an http client to communicate with the server that has our inbound handlers set above
	client := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return server, serverURL, client
}

func CreateMockHTTPServerAndClientNotOKStatusCode(t *testing.T) (net.Listener, string, *http.Client) {
	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(501)
	})

	return CreateMockHTTPServerAndClient(t, hf)
}

func startMockServer(handler http.Handler) net.Listener {
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatalf("HTTP listener failed to start: %s", err)
	}

	go func() {
		err := http.ServeTLS(listener, handler, certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			logger.Fatalf("HTTP server failed to start: %s", err)
		}
	}()

	return listener
}

func getServerPort(server net.Listener) int {
	// read dynamic port assigned to the server to be used by the client
	return server.Addr().(*net.TCPAddr).Port
}

func addCertsToCertPool(pool *x509.CertPool) error {
	var rawCerts []string

	// add contents of ec-pubCert(1, 2 and 3).pem to rawCerts
	for i := 1; i <= 3; i++ {
		certPath := fmt.Sprintf("%sec-pubCert%d.pem", certPrefix, i)
		// Create a pool with server certificates
		cert, e := ioutil.ReadFile(filepath.Clean(certPath))
		if e != nil {
			return fmt.Errorf("reading certificate failed: %w", e)
		}

		rawCerts = append(rawCerts, string(cert))
	}

	certs := decodeCerts(rawCerts)
	for i := range certs {
		pool.AddCert(certs[i])
	}

	return nil
}

// decodeCerts will decode a list of pemCertsList (string) into a list of x509 certificates.
func decodeCerts(pemCertsList []string) []*x509.Certificate {
	var certs []*x509.Certificate

	for _, pemCertsString := range pemCertsList {
		pemCerts := []byte(pemCertsString)
		for len(pemCerts) > 0 {
			var block *pem.Block

			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			certs = append(certs, cert)
		}
	}

	return certs
}

var errFailingMarshal = errors.New("failingMarshal always fails")

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

var errFailingUnmarshal = errors.New("failingUnmarshal always fails")

func failingUnmarshal([]byte, interface{}) error {
	return errFailingUnmarshal
}

type errFailingCloser struct{}

func (c *errFailingCloser) Close() error {
	return errors.New("errFailingCloser always fails")
}

func mockAddHeadersFuncSuccess(req *http.Request) (*http.Header, error) {
	// mocking a call to an auth server to get necessary credentials.
	// It only sets mock http.Header entries for testing purposes.
	req.Header.Set("controller", "mockController")
	req.Header.Set("authServerURL", "mockAuthServerURL")
	req.Header.Set("secret", "mockSecret")

	return &req.Header, nil
}

var errAddHeadersFunc = errors.New("mockAddHeadersFuncError always fails")

func mockAddHeadersFuncError(_ *http.Request) (*http.Header, error) {
	return nil, errAddHeadersFunc
}
