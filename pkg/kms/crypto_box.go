/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// TODO: move CryptoBox out of the KMS package.
//   this currently only sits inside KMS so it can access private keys. See issue #511

// CryptoBox provides an elliptic-curve-based authenticated encryption scheme
//
// Payloads are encrypted using symmetric encryption (XChacha20Poly1305)
// using a shared key derived from a shared secret created by
//   Curve25519 Elliptic Curve Diffie-Hellman key exchange.
//
// CryptoBox is created by a KMS, and reads secret keys from the KMS
//   for encryption/decryption, so clients do not need to see
//   the secrets themselves.
type CryptoBox struct {
	km *BaseKMS
}

// NewCryptoBox creates a CryptoBox which provides crypto box encryption using the given KMS's keypairs
func NewCryptoBox(w KeyManager) (*CryptoBox, error) {
	wa, ok := w.(*BaseKMS)
	if !ok {
		return nil, fmt.Errorf("cannot use parameter as KMS")
	}

	return &CryptoBox{km: wa}, nil
}

// Easy seals a message with a provided nonce
// theirPub is used as a public key, while myPub is used to identify the private key that should be used
func (b *CryptoBox) Easy(payload, nonce, theirPub, myPub []byte) ([]byte, error) {
	var recPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(recPubBytes[:], theirPub)

	//	 myPub is used to get the sender private key for encryption
	kp, err := b.km.getKeyPairSet(base58.Encode(myPub))
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], kp.EncKeyPair.Priv)
	copy(nonceBytes[:], nonce)

	ret := box.Seal(nil, payload, &nonceBytes, &recPubBytes, &priv)

	return ret, nil
}

// EasyOpen unseals a message sealed with Easy, where the nonce is provided
// theirPub is the public key used to decrypt directly, while myPub is used to identify the private key to be used
func (b *CryptoBox) EasyOpen(cipherText, nonce, theirPub, myPub []byte) ([]byte, error) {
	//	 myPub is used to get the recipient private key for decryption
	var sendPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(sendPubBytes[:], theirPub)

	kp, err := b.km.getKeyPairSet(base58.Encode(myPub))
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], kp.EncKeyPair.Priv)
	copy(nonceBytes[:], nonce)

	out, success := box.Open(nil, cipherText, &nonceBytes, &sendPubBytes, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}

// Seal seals a payload using the equivalent of libsodium box_seal
//
// Generates an ephemeral keypair to use for the sender, and includes
// the ephemeral sender public key in the message.
func (b *CryptoBox) Seal(payload, theirPub []byte, randSource io.Reader) ([]byte, error) {
	// generate ephemeral curve25519 asymmetric keys
	epk, esk, err := box.GenerateKey(randSource)
	if err != nil {
		return nil, err
	}

	var recPubBytes [cryptoutil.Curve25519KeySize]byte

	copy(recPubBytes[:], theirPub)

	nonce, err := cryptoutil.Nonce(epk[:], theirPub)
	if err != nil {
		return nil, err
	}

	// now seal the msg with the ephemeral key, nonce and recPub (which is recipient's publicKey)
	ret := box.Seal(epk[:], payload, nonce, &recPubBytes, esk)

	return ret, nil
}

// SealOpen decrypts a payload encrypted with Seal
//
// Reads the ephemeral sender public key, prepended to a properly-formatted message,
// and uses that along with the recipient private key corresponding to recPub to decrypt the message.
func (b *CryptoBox) SealOpen(cipherText, myPub []byte) ([]byte, error) {
	if len(cipherText) < cryptoutil.Curve25519KeySize {
		return nil, errors.New("message too short")
	}

	kp, err := b.km.getKeyPairSet(base58.Encode(myPub))
	if err != nil {
		return nil, err
	}

	var (
		epk  [cryptoutil.Curve25519KeySize]byte
		priv [cryptoutil.Curve25519KeySize]byte
	)

	copy(epk[:], cipherText[:cryptoutil.Curve25519KeySize])
	copy(priv[:], kp.EncKeyPair.Priv)

	nonce, err := cryptoutil.Nonce(epk[:], myPub)
	if err != nil {
		return nil, err
	}

	out, success := box.Open(nil, cipherText[cryptoutil.Curve25519KeySize:], nonce, &epk, &priv)
	if !success {
		return nil, errors.New("failed to unpack")
	}

	return out, nil
}
