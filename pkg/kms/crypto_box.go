/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kms

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/nacl/box"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
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

	// myPub is used to get the sender private key for encryption by fetching the corresponding KeySet first
	// derive KeySetID from the public signature key
	ksID := hashKeySetID(myPub)

	ks, err := b.km.getKeySet(ksID)
	if err != nil {
		return nil, err
	}

	privKey, err := b.findEncPrivKey(ks)
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], privKey)
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

	// myPub is used to get the sender private key for encryption
	ksID := hashKeySetID(myPub)

	ks, err := b.km.getKeySet(ksID)
	if err != nil {
		return nil, err
	}

	privKey, err := b.findEncPrivKey(ks)
	if err != nil {
		return nil, err
	}

	var (
		priv       [cryptoutil.Curve25519KeySize]byte
		nonceBytes [cryptoutil.NonceSize]byte
	)

	copy(priv[:], privKey)
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

	keySetID := hashKeySetID(myPub)

	ks, err := b.km.getKeySet(keySetID)
	if err != nil {
		return nil, err
	}

	var (
		epk  [cryptoutil.Curve25519KeySize]byte
		priv [cryptoutil.Curve25519KeySize]byte
	)

	copy(epk[:], cipherText[:cryptoutil.Curve25519KeySize])

	privKey, err := b.findEncPrivKey(ks)
	if err != nil {
		return nil, err
	}

	copy(priv[:], privKey)

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

// findEncPrivKey will loop through the list of keys in keySet and return the encryption private sub key
func (b *CryptoBox) findEncPrivKey(keySet *cryptoutil.KeySet) ([]byte, error) {
	ks := keySet
	// KeySet with 2 keys has ID hashed from the public encryption key, this means fetch the KeySet with ID
	// hashed from the publc signature key first.
	if len(ks.Keys) == 2 {
		sigPubKey, e := b.km.getKey(ks.PrimaryKey.ID)
		if e != nil {
			return nil, e
		}

		ksID := hashKeySetID(base58.Decode(sigPubKey.Value))

		fullKs, e := b.km.getKeySet(ksID)
		if e != nil {
			return nil, e
		}

		ks = fullKs
	}

	return b.findEncPrivKeyFromList(ks.Keys)
}

func (b *CryptoBox) findEncPrivKeyFromList(keys []cryptoutil.Key) ([]byte, error) {
	for _, key := range keys {
		simpleKey, err := b.km.getKey(key.ID)
		if err != nil {
			if !errors.Is(storage.ErrDataNotFound, err) {
				return nil, err
			}

			continue
		}

		if simpleKey.Alg == cryptoutil.Curve25519 && simpleKey.Capability == cryptoutil.Encryption {
			id, err := base64.RawURLEncoding.DecodeString(simpleKey.ID)
			if err != nil {
				return nil, err
			}

			// return private encryption key (id appended with 'es')
			if len(id) == 34 && id[32] == 'e' && id[33] == 's' {
				return base58.Decode(simpleKey.Value), nil
			}
		}
	}

	return nil, errors.New("no matching key found in KeySet")
}
