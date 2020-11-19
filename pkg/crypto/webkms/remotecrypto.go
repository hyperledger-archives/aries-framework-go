/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	webkmsimpl "github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
)

var logger = log.New("aries-framework/crypto/webkms")

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

type signResp struct {
	Signature string `json:"signature,omitempty"`
}

type verifyReq struct {
	Signature string `json:"signature,omitempty"`
	Message   string `json:"message,omitempty"`
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
	httpClient     *http.Client
	keystoreURL    string
	marshalFunc    marshalFunc
	unmarshalFunc  unmarshalFunc
	addHeadersOpts *webkmsimpl.HeadersOpts
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
)

// New creates a new remoteCrypto instance using http client connecting to keystoreURL.
func New(keystoreURL string, client *http.Client, headersOpts ...webkmsimpl.HeadersOpt) *RemoteCrypto {
	hOpts := webkmsimpl.NewOpt()

	for _, opt := range headersOpts {
		opt(hOpts)
	}

	return &RemoteCrypto{
		httpClient:     client,
		keystoreURL:    keystoreURL,
		marshalFunc:    json.Marshal,
		unmarshalFunc:  json.Unmarshal,
		addHeadersOpts: hOpts,
	}
}

func (r *RemoteCrypto) postHTTPRequest(destination string, mReq []byte) (*http.Response, error) {
	return r.doHTTPRequest(http.MethodPost, destination, mReq)
}

func (r *RemoteCrypto) doHTTPRequest(method, destination string, mReq []byte) (*http.Response, error) {
	httpReq, err := http.NewRequest(method, destination, bytes.NewBuffer(mReq))
	if err != nil {
		return nil, fmt.Errorf("build request error: %w", err)
	}

	if method == http.MethodPost {
		httpReq.Header.Set("Content-Type", webkmsimpl.ContentType)
	}

	if r.addHeadersOpts.HeadersFunc != nil {
		httpHeaders, err := r.addHeadersOpts.HeadersFunc(httpReq)
		if err != nil {
			return nil, fmt.Errorf("add optional request headers error: %w", err)
		}

		if httpHeaders != nil {
			httpReq.Header = httpHeaders.Clone()
		}
	}

	return r.httpClient.Do(httpReq)
}

// Encrypt will remotely encrypt msg and aad using a matching AEAD primitive in a remote key handle at keyURL of
// a public key.
// returns:
// 		cipherText in []byte
//		nonce in []byte
//		error in case of errors during encryption
func (r *RemoteCrypto) Encrypt(msg, aad []byte, keyURL interface{}) ([]byte, []byte, error) {
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

	return keyBytes, nonceBytes, nil
}

// Decrypt will remotely decrypt cipher with aad and given nonce using a matching AEAD primitive in a remote key handle
// at keyURL of a private key.
// returns:
//		plainText in []byte
//		error in case of errors
func (r *RemoteCrypto) Decrypt(cipher, aad, nonce []byte, keyURL interface{}) ([]byte, error) {
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

	return plaintTextBytes, nil
}

// Sign will remotely sign msg using a matching signature primitive in remote kh key handle at keyURL of a private key.
// returns:
// 		signature in []byte
//		error in case of errors
func (r *RemoteCrypto) Sign(msg []byte, keyURL interface{}) ([]byte, error) {
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

	return keyBytes, nil
}

// Verify will remotely verify a signature for the given msg using a matching signature primitive in a remote key
// handle at keyURL of a public key.
// returns:
// 		error in case of errors or nil if signature verification was successful
func (r *RemoteCrypto) Verify(signature, msg []byte, keyURL interface{}) error {
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

	return nil
}

// ComputeMAC remotely computes message authentication code (MAC) for code data with key at keyURL.
// using a matching MAC primitive in kh key handle.
func (r *RemoteCrypto) ComputeMAC(data []byte, keyURL interface{}) ([]byte, error) {
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

	return macBytes, nil
}

// VerifyMAC remotely determines if mac is a correct authentication code (MAC) for data using a key at KeyURL
// using a matching MAC primitive in kh key handle and returns nil if so, otherwise it returns an error.
func (r *RemoteCrypto) VerifyMAC(mac, data []byte, keyURL interface{}) error {
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

	// if senderURL is set, extract keyID and add it to the request (for ECDH-1PU wrapping)
	if senderURL != "" {
		senderURLStr := fmt.Sprintf("%s", senderURL)
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

	httpResp := &wrapKeyResp{}

	err = r.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal wrapKeyResp for WrapKey failed [%s, %w]", destination, err)
	}

	wrappedKey, err := serializableToWrappedKey(&httpResp.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("convert http request of wrapKeyResp for WrapKey failed [%s, %w]", destination, err)
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

	// is senderURL is set, extract keyID and add it to the request (for ECDH-1PU unwrapping)
	if senderURL != "" {
		senderURLStr := fmt.Sprintf("%s", senderURL)
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
	if err != nil {
		return nil, err
	}

	return keyBytes, nil
}

// closeResponseBody closes the response body.
//nolint: interfacer // don't want to add test stretcher logger here
func closeResponseBody(respBody io.Closer, logger log.Logger, action string) {
	err := respBody.Close()
	if err != nil {
		logger.Errorf("Failed to close response body for '%s' REST call: %s", action, err.Error())
	}
}
