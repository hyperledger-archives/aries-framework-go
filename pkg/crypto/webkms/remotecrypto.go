/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/bluele/gcache"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	webkmsimpl "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	spi "github.com/hyperledger/aries-framework-go/spi/log"
)

var logger = log.New("aries-framework/crypto/webkms")

// HTTPClient interface for the http client.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type encryptReq struct {
	Message        string `json:"message,omitempty"`
	AdditionalData string `json:"aad,omitempty"`
}

type encryptResp struct {
	CipherText string `json:"cipherText,omitempty"`
	Nonce      string `json:"nonce,omitempty"`
}

type decryptReq struct {
	CipherText     string `json:"cipherText,omitempty"`
	AdditionalData string `json:"aad,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
}

type decryptResp struct {
	PlainText string `json:"plainText,omitempty"`
}

type signReq struct {
	Message string `json:"message,omitempty"`
}

type signMultiReq struct {
	Messages []string `json:"messages,omitempty"`
}

type deriveProofReq struct {
	Messages        []string `json:"messages,omitempty"`
	Signature       string   `json:"signature,omitempty"`
	Nonce           string   `json:"nonce,omitempty"`
	RevealedIndexes []int    `json:"revealedIndexes,omitempty"`
}

type signResp struct {
	Signature string `json:"signature,omitempty"`
}

type deriveProofResp struct {
	Proof string `json:"proof,omitempty"`
}

type verifyReq struct {
	Signature string `json:"signature,omitempty"`
	Message   string `json:"message,omitempty"`
}

type verifyProofReq struct {
	Proof    string   `json:"proof,omitempty"`
	Messages []string `json:"messages,omitempty"`
	Nonce    string   `json:"nonce,omitempty"`
}

type verifyMultiReq struct {
	Signature string   `json:"signature,omitempty"`
	Messages  []string `json:"messages,omitempty"`
}

type computeMACReq struct {
	Data string `json:"data,omitempty"`
}

type computeMACResp struct {
	MAC string `json:"mac,omitempty"`
}

type verifyMACReq struct {
	MAC  string `json:"mac,omitempty"`
	Data string `json:"data,omitempty"`
}

type marshalFunc func(interface{}) ([]byte, error)

type unmarshalFunc func([]byte, interface{}) error

// RemoteCrypto implementation of kms.KeyManager api.
type RemoteCrypto struct {
	httpClient    HTTPClient
	keystoreURL   string
	marshalFunc   marshalFunc
	unmarshalFunc unmarshalFunc
	opts          *webkmsimpl.Opts
}

const (
	keysURI       = "/keys"
	encryptURI    = "/encrypt"
	decryptURI    = "/decrypt"
	signURI       = "/sign"
	verifyURI     = "/verify"
	computeMACURI = "/computemac"
	verifyMACURI  = "/verifymac"
	wrapURI       = "/wrap"
	unwrapURI     = "/unwrap"

	// multi signatures/selective disclosure crypto (eg BBS+) endpoints.
	signMultiURI   = "/signmulti"
	verifyMultiURI = "/verifymulti"
	deriveProofURI = "/deriveproof"
	verifyProofURI = "/verifyproof"
)

// New creates a new remoteCrypto instance using http client connecting to keystoreURL.
func New(keystoreURL string, client HTTPClient, opts ...webkmsimpl.Opt) *RemoteCrypto {
	rOpts := webkmsimpl.NewOpt()

	for _, opt := range opts {
		opt(rOpts)
	}

	return &RemoteCrypto{
		httpClient:    client,
		keystoreURL:   keystoreURL,
		marshalFunc:   json.Marshal,
		unmarshalFunc: json.Unmarshal,
		opts:          rOpts,
	}
}

func (r *RemoteCrypto) postHTTPRequest(destination string, mReq []byte) (*http.Response, error) {
	return r.doHTTPRequest(http.MethodPost, destination, mReq)
}

func (r *RemoteCrypto) doHTTPRequest(method, destination string, mReq []byte) (*http.Response, error) {
	start := time.Now()

	httpReq, err := http.NewRequest(method, destination, bytes.NewBuffer(mReq))
	if err != nil {
		return nil, fmt.Errorf("build request error: %w", err)
	}

	if method == http.MethodPost {
		httpReq.Header.Set("Content-Type", webkmsimpl.ContentType)
	}

	if r.opts.HeadersFunc != nil {
		httpHeaders, e := r.opts.HeadersFunc(httpReq)
		if e != nil {
			return nil, fmt.Errorf("add optional request headers error: %w", e)
		}

		if httpHeaders != nil {
			httpReq.Header = httpHeaders.Clone()
		}
	}

	resp, err := r.httpClient.Do(httpReq)

	logger.Debugf("  HTTP %s %s call duration: %s", method, destination, time.Since(start))

	return resp, err
}

// Encrypt will remotely encrypt msg and aad using a matching AEAD primitive in a remote key handle at keyURL of
// a public key.
// returns:
// 		cipherText in []byte
//		nonce in []byte
//		error in case of errors during encryption
func (r *RemoteCrypto) Encrypt(msg, aad []byte, keyURL interface{}) ([]byte, []byte, error) {
	startEncrypt := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + encryptURI

	eReq := encryptReq{
		Message:        base64.URLEncoding.EncodeToString(msg),
		AdditionalData: base64.URLEncoding.EncodeToString(aad),
	}

	httpReqBytes, err := r.marshalFunc(eReq)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal encryption request for Encrypt failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("posting Encrypt plaintext failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Encrypt")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read encryption response for Encrypt failed [%s, %w]", destination, err)
	}

	httpResp := &encryptResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, nil, fmt.Errorf("unmarshal encryption for Encrypt failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.CipherText)
	if err != nil {
		return nil, nil, err
	}

	nonceBytes, err := base64.URLEncoding.DecodeString(httpResp.Nonce)
	if err != nil {
		return nil, nil, err
	}

	logger.Debugf("overall Encrypt duration: %s", time.Since(startEncrypt))

	return keyBytes, nonceBytes, nil
}

// Decrypt will remotely decrypt cipher with aad and given nonce using a matching AEAD primitive in a remote key handle
// at keyURL of a private key.
// returns:
//		plainText in []byte
//		error in case of errors
func (r *RemoteCrypto) Decrypt(cipher, aad, nonce []byte, keyURL interface{}) ([]byte, error) {
	startDecrypt := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + decryptURI

	dReq := decryptReq{
		CipherText:     base64.URLEncoding.EncodeToString(cipher),
		Nonce:          base64.URLEncoding.EncodeToString(nonce),
		AdditionalData: base64.URLEncoding.EncodeToString(aad),
	}

	httpReqBytes, err := r.marshalFunc(dReq)
	if err != nil {
		return nil, fmt.Errorf("marshal decryption request for Decrypt failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting Decrypt ciphertext failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Decrypt")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read decryption response for Decrypt failed [%s, %w]", destination, err)
	}

	httpResp := &decryptResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal decryption for Decrypt failed [%s, %w]", destination, err)
	}

	plaintTextBytes, err := base64.URLEncoding.DecodeString(httpResp.PlainText)
	if err != nil {
		return nil, err
	}

	logger.Debugf("overall Decrypt duration: %s", time.Since(startDecrypt))

	return plaintTextBytes, nil
}

// Sign will remotely sign msg using a matching signature primitive in remote kh key handle at keyURL of a private key.
// returns:
// 		signature in []byte
//		error in case of errors
func (r *RemoteCrypto) Sign(msg []byte, keyURL interface{}) ([]byte, error) {
	startSign := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + signURI

	sReq := signReq{
		Message: base64.URLEncoding.EncodeToString(msg),
	}

	httpReqBytes, err := r.marshalFunc(sReq)
	if err != nil {
		return nil, fmt.Errorf("marshal signature request for Sign failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting Sign message failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Sign")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read signature response for Sign failed [%s, %w]", destination, err)
	}

	httpResp := &signResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signature for Sign failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.Signature)
	if err != nil {
		return nil, err
	}

	logger.Debugf("overall Sign duration: %s", time.Since(startSign))

	return keyBytes, nil
}

// Verify will remotely verify a signature for the given msg using a matching signature primitive in a remote key
// handle at keyURL of a public key.
// returns:
// 		error in case of errors or nil if signature verification was successful
func (r *RemoteCrypto) Verify(signature, msg []byte, keyURL interface{}) error {
	startVerify := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + verifyURI

	vReq := verifyReq{
		Message:   base64.URLEncoding.EncodeToString(msg),
		Signature: base64.URLEncoding.EncodeToString(signature),
	}

	httpReqBytes, err := r.marshalFunc(vReq)
	if err != nil {
		return fmt.Errorf("marshal verify request for Verify failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return fmt.Errorf("posting Verify signature failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Verify")

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("posting Verify signature returned http error: %s", resp.Status)
	}

	logger.Debugf("overall Verify duration: %s", time.Since(startVerify))

	return nil
}

// ComputeMAC remotely computes message authentication code (MAC) for code data with key at keyURL.
// using a matching MAC primitive in kh key handle.
func (r *RemoteCrypto) ComputeMAC(data []byte, keyURL interface{}) ([]byte, error) { //nolint: gocyclo
	keyHash := string(sha256.New().Sum([]byte(fmt.Sprintf("%s_%s", keyURL, data))))

	if r.opts.ComputeMACCache != nil {
		v, err := r.opts.ComputeMACCache.Get(keyHash)
		if err == nil {
			return v.([]byte), nil
		}

		if !errors.Is(err, gcache.KeyNotFoundError) {
			return nil, err
		}
	}

	startComputeMAC := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + computeMACURI

	mReq := computeMACReq{
		Data: base64.URLEncoding.EncodeToString(data),
	}

	httpReqBytes, err := r.marshalFunc(mReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request for ComputeMAC failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting ComputeMAC request failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "ComputeMAC")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response for ComputeMAC failed [%s, %w]", destination, err)
	}

	httpResp := &computeMACResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ComputeMAC response failed [%s, %w]", destination, err)
	}

	macBytes, err := base64.URLEncoding.DecodeString(httpResp.MAC)
	if err != nil {
		return nil, err
	}

	if r.opts.ComputeMACCache != nil {
		if err := r.opts.ComputeMACCache.Set(keyHash, macBytes); err != nil {
			return nil, fmt.Errorf("failed to store in cache: %w", err)
		}
	}

	logger.Debugf("overall ComputeMAC duration: %s", time.Since(startComputeMAC))

	return macBytes, nil
}

// VerifyMAC remotely determines if mac is a correct authentication code (MAC) for data using a key at KeyURL
// using a matching MAC primitive in kh key handle and returns nil if so, otherwise it returns an error.
func (r *RemoteCrypto) VerifyMAC(mac, data []byte, keyURL interface{}) error {
	startVerifyMAC := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + verifyMACURI

	vReq := verifyMACReq{
		MAC:  base64.URLEncoding.EncodeToString(mac),
		Data: base64.URLEncoding.EncodeToString(data),
	}

	httpReqBytes, err := r.marshalFunc(vReq)
	if err != nil {
		return fmt.Errorf("marshal request for VerifyMAC failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return fmt.Errorf("posting VerifyMAC request failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "VerifyMAC")

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("posting VerifyMAC request returned http error: %s", resp.Status)
	}

	logger.Debugf("overall VerifyMAC duration: %s", time.Since(startVerifyMAC))

	return nil
}

// WrapKey will remotely execute key wrapping of cek using apu, apv and recipient public key 'recPubKey'.
// 'opts' allows setting the option sender key handle using WithSender() option where the sender key handle consists
// of a remote key located in the option as a keyURL. This option allows ECDH-1PU key wrapping (aka Authcrypt).
// The absence of this option uses ECDH-ES key wrapping (aka Anoncrypt).
// 		RecipientWrappedKey containing the wrapped cek value
// 		error in case of errors
func (r *RemoteCrypto) WrapKey(cek, apu, apv []byte, recPubKey *crypto.PublicKey,
	opts ...crypto.WrapKeyOpts) (*crypto.RecipientWrappedKey, error) {
	startWrapKey := time.Now()
	destination := r.keystoreURL + wrapURI

	pOpts := crypto.NewOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	senderURL := pOpts.SenderKey()
	recipientPubKey := pubKeyToSerializableReq(recPubKey)
	wReq := &wrapKeyReq{
		CEK:       base64.URLEncoding.EncodeToString(cek),
		APU:       base64.URLEncoding.EncodeToString(apu),
		APV:       base64.URLEncoding.EncodeToString(apv),
		RecPubKey: recipientPubKey,
	}

	senderURLStr := fmt.Sprintf("%s", senderURL)

	var nilVal interface{}

	// if senderURL is set, extract keyID and add it to the request (for ECDH-1PU wrapping)
	if senderURLStr != "" && senderURLStr != fmt.Sprintf("%s", nilVal) {
		senderKID := senderURLStr[strings.LastIndex(senderURLStr, keysURI)+len(keysURI):]
		// TODO key server must store the sender public key in the recipient's keystore (or by means of a
		//  third party store). Need to confirm what needs to be done to make Authcrypt key wrapping work on the
		//  key server side.
		wReq.SenderKID = senderKID
	}

	httpReqBytes, err := r.marshalFunc(wReq)
	if err != nil {
		return nil, fmt.Errorf("marshal wrapKeyReq for WrapKey failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting WrapKey failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "WrapKey")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read wrap key response for WrapKey failed [%s, %w]", destination, err)
	}

	rwk, err := r.buildWrappedKeyResponse(respBody, destination)

	logger.Debugf("overall WrapKey duration: %s", time.Since(startWrapKey))

	return rwk, err
}

func (r *RemoteCrypto) buildWrappedKeyResponse(respBody []byte, dest string) (*crypto.RecipientWrappedKey, error) {
	httpResp := &wrapKeyResp{}

	err := r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal wrapKeyResp for WrapKey failed [%s, %w]", dest, err)
	}

	wrappedKey, err := serializableToWrappedKey(&httpResp.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("convert http request of wrapKeyResp for WrapKey failed [%s, %w]", dest, err)
	}

	return wrappedKey, nil
}

// UnwrapKey remotely unwraps a key in recWK using recipient private key found at keyURL.
// 'opts' allows setting the option sender key handle using WithSender() optionwhere the sender key handle consists
// of a remote key located in the option as a keyURL. This options allows ECDH-1PU key unwrapping (aka Authcrypt).
// The absence of this option uses ECDH-ES key unwrapping (aka Anoncrypt).
// returns:
// 		unwrapped key in raw bytes
// 		error in case of errors
func (r *RemoteCrypto) UnwrapKey(recWK *crypto.RecipientWrappedKey, keyURL interface{},
	opts ...crypto.WrapKeyOpts) ([]byte, error) {
	startUnwrapKey := time.Now()
	destination := fmt.Sprintf("%s", keyURL) + unwrapURI

	pOpts := crypto.NewOpt()

	for _, opt := range opts {
		opt(pOpts)
	}

	senderURL := pOpts.SenderKey()
	httpWK := wrappedKeyToSerializableReq(recWK)
	uReq := unwrapKeyReq{
		WrappedKey: httpWK,
	}

	senderURLStr := fmt.Sprintf("%s", senderURL)

	var nilVal interface{}

	// is senderURL is set, extract keyID and add it to the request (for ECDH-1PU unwrapping)
	if senderURLStr != "" && senderURLStr != fmt.Sprintf("%s", nilVal) {
		senderKID := senderURLStr[strings.LastIndex(senderURLStr, keysURI)+len(keysURI):]
		uReq.SenderKID = base64.URLEncoding.EncodeToString([]byte(senderKID))
	}

	httpReqBytes, err := r.marshalFunc(uReq)
	if err != nil {
		return nil, fmt.Errorf("marshal unwrapKeyReq for UnwrapKey failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting UnwrapKey failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "UnwrapKey")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read unwrapped key response for UnwrapKey failed [%s, %w]", destination, err)
	}

	httpResp := &unwrapKeyResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal unwrapKeyResp for UnwrapKey failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.Key)

	logger.Debugf("overall UnwrapKey duration: %s", time.Since(startUnwrapKey))

	return keyBytes, err
}

// SignMulti will create a BBS+ signature of messages using the signer's private key handle found at signerKeyURL.
// returns:
// 		signature in []byte
//		error in case of errors
func (r *RemoteCrypto) SignMulti(messages [][]byte, signerKeyURL interface{}) ([]byte, error) {
	startSign := time.Now()
	destination := fmt.Sprintf("%s", signerKeyURL) + signMultiURI

	var encMessages []string
	for _, msg := range messages {
		encMessages = append(encMessages, base64.URLEncoding.EncodeToString(msg))
	}

	sReq := signMultiReq{
		Messages: encMessages,
	}

	httpReqBytes, err := r.marshalFunc(sReq)
	if err != nil {
		return nil, fmt.Errorf("marshal signature request for BBS+ Sign failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting BBS+ Sign message failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "BBS+ Sign")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read signature response for BBS+ Sign failed [%s, %w]", destination, err)
	}

	httpResp := &signResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal signature for BBS+ Sign failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.Signature)
	if err != nil {
		return nil, err
	}

	logger.Debugf("overall BBS+ Sign duration: %s", time.Since(startSign))

	return keyBytes, nil
}

// VerifyMulti will BBS+ verify a signature of messages against the signer's public key handle found at signerKeyURL.
// returns:
// 		error in case of errors or nil if signature verification was successful
func (r *RemoteCrypto) VerifyMulti(messages [][]byte, signature []byte, signerKeyURL interface{}) error {
	startVerify := time.Now()
	destination := fmt.Sprintf("%s", signerKeyURL) + verifyMultiURI

	var encMessages []string
	for _, msg := range messages {
		encMessages = append(encMessages, base64.URLEncoding.EncodeToString(msg))
	}

	vReq := verifyMultiReq{
		Messages:  encMessages,
		Signature: base64.URLEncoding.EncodeToString(signature),
	}

	httpReqBytes, err := r.marshalFunc(vReq)
	if err != nil {
		return fmt.Errorf("marshal verify request for BBS+ Verify failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return fmt.Errorf("posting BBS+ Verify signature failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "BBS+ Verify")

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("posting BBS+ Verify signature returned http error: %s", resp.Status)
	}

	logger.Debugf("overall BBS+ Verify duration: %s", time.Since(startVerify))

	return nil
}

// VerifyProof will verify a BBS+ signature proof (generated e.g. by Verifier's DeriveProof() call) for revealedMessages
// with the signer's public key handle found at signerKeyURL.
// returns:
// 		error in case of errors or nil if signature proof verification was successful
func (r *RemoteCrypto) VerifyProof(revealedMessages [][]byte, proof, nonce []byte, signerKeyURL interface{}) error {
	startVerifyProof := time.Now()
	destination := fmt.Sprintf("%s", signerKeyURL) + verifyProofURI

	var encMessages []string
	for _, msg := range revealedMessages {
		encMessages = append(encMessages, base64.URLEncoding.EncodeToString(msg))
	}

	vReq := verifyProofReq{
		Messages: encMessages,
		Proof:    base64.URLEncoding.EncodeToString(proof),
		Nonce:    base64.URLEncoding.EncodeToString(nonce),
	}

	httpReqBytes, err := r.marshalFunc(vReq)
	if err != nil {
		return fmt.Errorf("marshal request for BBS+ Verify proof failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return fmt.Errorf("posting BBS+ Verify proof failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "BBS+ Verify Proof")

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("posting BBS+ Verify proof returned http error: %s", resp.Status)
	}

	logger.Debugf("overall BBS+ Verify proof duration: %s", time.Since(startVerifyProof))

	return nil
}

// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature (can be built
// using a Signer's SignMulti() call) and the signer's public key handle found at signerKeyURL.
// returns:
// 		signature proof in []byte
//		error in case of errors
func (r *RemoteCrypto) DeriveProof(messages [][]byte, bbsSignature, nonce []byte, revealedIndexes []int,
	signerKeyURL interface{}) ([]byte, error) {
	startDeriveProof := time.Now()
	destination := fmt.Sprintf("%s", signerKeyURL) + deriveProofURI

	var encMessages []string
	for _, msg := range messages {
		encMessages = append(encMessages, base64.URLEncoding.EncodeToString(msg))
	}

	sReq := deriveProofReq{
		Messages:        encMessages,
		Signature:       base64.URLEncoding.EncodeToString(bbsSignature),
		Nonce:           base64.URLEncoding.EncodeToString(nonce),
		RevealedIndexes: revealedIndexes,
	}

	httpReqBytes, err := r.marshalFunc(sReq)
	if err != nil {
		return nil, fmt.Errorf("marshal request for BBS+ Derive proof failed [%s, %w]", destination, err)
	}

	resp, err := r.postHTTPRequest(destination, httpReqBytes)
	if err != nil {
		return nil, fmt.Errorf("posting BBS+ Derive proof message failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "BBS+ Derive Proof")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read signature response for BBS+ Derive proof failed [%s, %w]", destination, err)
	}

	httpResp := &deriveProofResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal request for BBS+ Derive proof failed [%s, %w]", destination, err)
	}

	keyBytes, err := base64.URLEncoding.DecodeString(httpResp.Proof)
	if err != nil {
		return nil, err
	}

	logger.Debugf("overall BBS+ Derive proof duration: %s", time.Since(startDeriveProof))

	return keyBytes, nil
}

// closeResponseBody closes the response body.
func closeResponseBody(respBody io.Closer, logger spi.Logger, action string) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body for '%s' REST call: %s", action, err.Error())
	}
}
