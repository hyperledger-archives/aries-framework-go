/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"fmt"
	"io"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// TODO move CryptoBox out of webkms package.
//  this currently only sits inside webkms so it can execute crypto with private keys remotely. See issue #511
// TODO delete this file and its corresponding test file when LegacyPacker is removed.

type easyReq struct {
	Payload  []byte `json:"payload"`
	Nonce    []byte `json:"nonce"`
	TheirPub []byte `json:"their_pub"`
}

type easyResp struct {
	Ciphertext []byte `json:"ciphertext"`
}

type easyOpenReq struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	TheirPub   []byte `json:"their_pub"`
	MyPub      []byte `json:"my_pub"`
}

type easyOpenResp struct {
	Plaintext []byte `json:"plaintext"`
}

type sealOpenReq struct {
	Ciphertext []byte `json:"ciphertext"`
	MyPub      []byte `json:"my_pub"`
}

type sealOpenResp struct {
	Plaintext []byte `json:"plaintext"`
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
	easyStart := time.Now()
	keyURL := b.km.buildKIDURL(myKID)

	destination := keyURL + easyURL

	httpReqJSON := &easyReq{
		Payload:  payload,
		Nonce:    nonce,
		TheirPub: theirPub,
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

	err = checkError(resp)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read ciphertext response for Easy failed [%s, %w]", destination, err)
	}

	httpResp := &easyResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal ciphertext for Easy failed [%s, %w]", destination, err)
	}

	logger.Debugf("overall Easy duration: %s", time.Since(easyStart))

	return httpResp.Ciphertext, nil
}

// EasyOpen remotely unseals a message sealed with Easy, where the nonce is provided.
// theirPub is the public key used to decrypt directly, while myPub is used to identify the private key to be used.
func (b *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	easyOpenStart := time.Now()
	destination := b.km.keystoreURL + easyOpenURL

	httpReqJSON := &easyOpenReq{
		Ciphertext: cipherText,
		Nonce:      nonce,
		TheirPub:   theirPub,
		MyPub:      myPub,
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

	err = checkError(resp)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read plaintext response for EasyOpen failed [%s, %w]", destination, err)
	}

	httpResp := &easyOpenResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal plaintext for EasyOpen failed [%s, %w]", destination, err)
	}

	logger.Debugf("overall easyOpen duration: %s", time.Since(easyOpenStart))

	return httpResp.Plaintext, nil
}

// Seal seals a payload using the equivalent of libsodium box_seal. This is an exact copy of localkms's CryptoBox.Seal()
// as no private key is involved and therefore it is not necessary to call the key server.
//
// Generates an ephemeral keypair to use for the sender, and includes
// the ephemeral sender public key in the message.
func (b *CryptoBox) Seal(payload, theirEncPub []byte, randSource io.Reader) ([]byte, error) {
	sealStart := time.Now()
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

	logger.Debugf("overall Seal (non remote call) duration: %s", time.Since(sealStart))

	return ret, nil
}

// SealOpen remotely decrypts a payload encrypted with Seal.
//
// Reads the ephemeral sender public key, prepended to a properly-formatted message,
// and uses that along with the recipient private key corresponding to myPub to decrypt the message.
func (b *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	sealOpenStart := time.Now()
	destination := b.km.keystoreURL + sealOpenURL

	httpReqJSON := &sealOpenReq{
		Ciphertext: cipherText,
		MyPub:      myPub,
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

	err = checkError(resp)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read plaintext response for SealOpen failed [%s, %w]", destination, err)
	}

	httpResp := &sealOpenResp{}

	err = b.km.unmarshalFunc(respBody, httpResp)
	if err != nil {
		return nil, fmt.Errorf("unmarshal plaintext for SealOpen failed [%s, %w]", destination, err)
	}

	logger.Debugf("overall SealOpen duration: %s", time.Since(sealOpenStart))

	return httpResp.Plaintext, nil
}
