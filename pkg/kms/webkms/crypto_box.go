/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"

	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// TODO move CryptoBox out of webkms package.
//  this currently only sits inside LocalKMS so it can access private keys. See issue #511
// TODO delete this file and its corresponding test file when LegacyPacker is removed.

type easyReq struct {
	Payload  string `json:"payload"`
	Nonce    string `json:"nonce"`
	TheirPub string `json:"theirPub"`
}

type easyResp struct {
	CipherText string `json:"cipherText"`
}

type easyOpenReq struct {
	CipherText string `json:"cipherText"`
	Nonce      string `json:"nonce"`
	TheirPub   string `json:"theirPub"`
	MyPub      string `json:"myPub"`
}

type easyOpenResp struct {
	PlainText string `json:"plainText"`
}

type sealOpenReq struct {
	CipherText string `json:"cipherText"`
	MyPub      string `json:"myPub"`
}

type sealOpenResp struct {
	PlainText string `json:"plainText"`
}

const (
	easyURL     = "/easy"
	easyOpenURL = "/easyopen"
	sealOpenURL = "/sealopen"
)

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme executed on a remote key server
//
// Payloads are encrypted using symmetric encryption (XChacha20Poly1305)
// using a shared key derived from a shared secret created by
//   Curve25519 Elliptic Curve Diffie-Hellman key exchange.
//
// CryptoBox is created by a remote KMS, and remotely reads secret keys from the KMS
//   for encryption/decryption, so clients do not need to see
//   the secrets themselves.
type CryptoBox struct {
	km *RemoteKMS
}

// NewCryptoBox creates a CryptoBox which provides remote crypto box encryption using the given KMS's key.
func NewCryptoBox(w kms.KeyManager) (*CryptoBox, error) {
	lkms, ok := w.(*RemoteKMS)
	if !ok {
		return nil, fmt.Errorf("cannot use parameter argument as KMS")
	}

	return &CryptoBox{km: lkms}, nil
}

// Easy remotely seals a message with a provided nonce
// theirPub is used as a public key, while myPub is used to identify the private key that should be used.
func (b *CryptoBox) Easy(payload, nonce, theirPub []byte, myKID string) ([]byte, error) {
	keyURL := b.km.buildKIDURL(myKID)

	destination := keyURL + easyURL

	httpReqJSON := &easyReq{
		Payload:  base64.URLEncoding.EncodeToString(payload),
		Nonce:    base64.URLEncoding.EncodeToString(nonce),
		TheirPub: base64.URLEncoding.EncodeToString(theirPub),
	}

	marshaledReq, err := b.km.marshalFunc(httpReqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Easy request [%s, %w]", destination, err)
	}

	resp, err := b.km.postHTTPRequest(destination, marshaledReq)
	if err != nil {
		return nil, fmt.Errorf("posting Easy request failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "Easy")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ciphertext response for Easy failed [%s, %w]", destination, err)
	}

	httpResp := &easyResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext for Easy failed [%s, %w]", destination, err)
	}

	ciphertext, err := base64.URLEncoding.DecodeString(httpResp.CipherText)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

// EasyOpen remotely unseals a message sealed with Easy, where the nonce is provided.
// theirPub is the public key used to decrypt directly, while myPub is used to identify the private key to be used.
func (b *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	destination := b.km.keystoreURL + easyOpenURL

	httpReqJSON := &easyOpenReq{
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		Nonce:      base64.URLEncoding.EncodeToString(nonce),
		TheirPub:   base64.URLEncoding.EncodeToString(theirPub),
		MyPub:      base64.URLEncoding.EncodeToString(myPub),
	}

	marshaledReq, err := b.km.marshalFunc(httpReqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EasyOpen request [%s, %w]", destination, err)
	}

	resp, err := b.km.postHTTPRequest(destination, marshaledReq)
	if err != nil {
		return nil, fmt.Errorf("posting EasyOpen failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "EasyOpen")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read plaintext response for EasyOpen failed [%s, %w]", destination, err)
	}

	httpResp := &easyOpenResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal plaintext for EasyOpen failed [%s, %w]", destination, err)
	}

	plainText, err := base64.URLEncoding.DecodeString(httpResp.PlainText)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

// Seal seals a payload using the equivalent of libsodium box_seal. This is an exact copy of localkms's CryptoBox.Seal()
// as no private key is involved and therefore it is not necessary to call the key server.
//
// Generates an ephemeral keypair to use for the sender, and includes
// the ephemeral sender public key in the message.
func (b *CryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	// generate ephemeral curve25519 asymmetric keys
	epk, esk, err := box.GenerateKey(randSource)
	if err != nil {
		return nil, err
	}

	var recPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(recPubBytes[:], theirEncPub)

	nonce, err := cryptoutil.Nonce(epk[:], theirEncPub)
	if err != nil {
		return nil, err
	}

	// now seal the msg with the ephemeral key, nonce and recPub (which is recipient's publicKey)
	ret := box.Seal(epk[:], payload, nonce, &recPubBytes, esk)

	return ret, nil
}

// SealOpen remotely decrypts a payload encrypted with Seal.
//
// Reads the ephemeral sender public key, prepended to a properly-formatted message,
// and uses that along with the recipient private key corresponding to myPub to decrypt the message.
func (b *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	destination := b.km.keystoreURL + sealOpenURL

	httpReqJSON := &sealOpenReq{
		CipherText: base64.URLEncoding.EncodeToString(cipherText),
		MyPub:      base64.URLEncoding.EncodeToString(myPub),
	}

	marshaledReq, err := b.km.marshalFunc(httpReqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SealOpen request [%s, %w]", destination, err)
	}

	resp, err := b.km.postHTTPRequest(destination, marshaledReq)
	if err != nil {
		return nil, fmt.Errorf("posting SealOpen failed [%s, %w]", destination, err)
	}

	// handle response
	defer closeResponseBody(resp.Body, logger, "SealOpen")

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read plaintext response for SealOpen failed [%s, %w]", destination, err)
	}

	httpResp := &sealOpenResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal plaintext for SealOpen failed [%s, %w]", destination, err)
	}

	plaintext, err := base64.URLEncoding.DecodeString(httpResp.PlainText)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
