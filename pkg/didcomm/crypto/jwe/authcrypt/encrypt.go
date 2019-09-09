/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	josecipher "github.com/square/go-jose/v3/cipher"
	"golang.org/x/crypto/blake2b"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/poly1305"
)

// Encrypt will JWE encode the payload argument for the sender and recipients
// Using (X)Chacha20 encryption algorithm and Poly1035 authenticator
// It will encrypt using the sender's keypair and the list of recipients arguments
func (c *Crypter) Encrypt(payload []byte, sender keyPair, recipients []*[chacha.KeySize]byte) ([]byte, error) { //nolint:lll,funlen
	if len(recipients) == 0 {
		return nil, errEmptyRecipients
	}

	if !IsKeyPairValid(sender) {
		return nil, errInvalidKeypair
	}

	headers := jweHeaders{
		"typ": "prs.hyperledger.aries-auth-message",
		"alg": "ECDH-SS+" + string(c.alg) + "KW",
		"enc": string(c.alg),
	}

	aad := buildAAD(recipients)
	aadEncoded := base64.RawURLEncoding.EncodeToString(aad)

	h, err := json.Marshal(headers)
	if err != nil {
		return nil, err
	}
	encHeaders := base64.RawURLEncoding.EncodeToString(h)
	// build the Payload's AAD string
	pldAAD := encHeaders + "." + aadEncoded

	// generate a new nonce for this encryption
	nonce := make([]byte, c.nonceSize)
	_, err = randReader.Read(nonce)
	if err != nil {
		return nil, err
	}
	nonceEncoded := base64.RawURLEncoding.EncodeToString(nonce)

	cek := &[chacha.KeySize]byte{}

	// generate a cek for encryption (it will be treated as a symmetric key)
	_, err = randReader.Read(cek[:])
	if err != nil {
		return nil, err
	}

	// create a cipher for the given nonceSize and generated cek above
	crypter, err := createCipher(c.nonceSize, cek[:])
	if err != nil {
		return nil, err
	}

	// encrypt payload using generated nonce, payload and its AAD
	// the output is a []byte containing the cipherText + tag
	symOutput := crypter.Seal(nil, nonce, payload, []byte(pldAAD))

	tagEncoded := extractTag(symOutput)
	cipherTextEncoded := extractCipherText(symOutput)

	// now build, encode recipients and include the encrypted cek (with a recipient's ephemeral key)
	encRec, err := c.encodeRecipients(cek, recipients, sender)
	if err != nil {
		return nil, err
	}

	jwe, err := c.buildJWE(encHeaders, encRec, aadEncoded, nonceEncoded, tagEncoded, cipherTextEncoded)
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

// extractTag extracts the base64UrlEncoded tag sub slice from symOutput returned by cipher.Seal
func extractTag(symOutput []byte) string {
	// symOutput has a length of len(clear msg) + poly1035.TagSize
	// fetch the tag from the tail of symOutput
	tag := symOutput[len(symOutput)-poly1305.TagSize:]

	// base64 encode the tag
	return base64.RawURLEncoding.EncodeToString(tag)
}

// extractCipherText extracts the base64UrlEncoded cipherText sub slice from symOutput returned by cipher.Seal
func extractCipherText(symOutput []byte) string {
	// fetch the cipherText from the head of symOutput (0:up to the trailing tag)
	cipherText := symOutput[0 : len(symOutput)-poly1305.TagSize]

	// base64 encode the cipherText
	return base64.RawURLEncoding.EncodeToString(cipherText)
}

// createCipher will create and return a new Chacha20Poly1035 cipher for the given nonceSize and symmetric key
func createCipher(nonceSize int, symKey []byte) (cipher.AEAD, error) {
	switch nonceSize {
	case chacha.NonceSize:
		return chacha.New(symKey)
	case chacha.NonceSizeX:
		return chacha.NewX(symKey)
	default:
		return nil, errors.New("cipher cannot be created with bad nonce size and shared symmetric Key combo")
	}
}

// buildJWE builds the JSON object representing the JWE output of the encryption
// and returns its marshaled []byte representation
func (c *Crypter) buildJWE(headers string, recipients []Recipient, aad, iv, tag, cipherText string) ([]byte, error) {
	jwe := Envelope{
		Protected:  headers,
		Recipients: recipients,
		AAD:        aad,
		IV:         iv,
		Tag:        tag,
		CipherText: cipherText,
	}

	jweBytes, err := json.Marshal(jwe)
	if err != nil {
		return nil, err
	}

	return jweBytes, nil
}

// buildAAD to build the Additional Authentication Data for the AEAD (chach20poly1035) cipher.
// the build takes the list of recipients keys base58 encoded and sorted then SHA256 hash
// the concatenation of these keys with a '.' separator
func buildAAD(recipients []*[chacha.KeySize]byte) []byte {
	var keys []string
	for _, r := range recipients {
		keys = append(keys, base58.Encode(r[:]))
	}
	return hashAAD(keys)
}

// hashAAD will string sort keys and return sha256 hash of the string representation
// of keys concatenated by '.'
func hashAAD(keys []string) []byte {
	sort.Strings(keys)
	sha := sha256.Sum256([]byte(strings.Join(keys, ".")))
	return sha[:]
}

// encodeRecipients will encode the sharedKey (cek) for each recipient
// and return a list of encoded recipient keys
func (c *Crypter) encodeRecipients(sharedSymKey *[chacha.KeySize]byte, recipients []*[chacha.KeySize]byte, senderKp keyPair) ([]Recipient, error) { //nolint:lll
	var encodedRecipients []Recipient
	for _, e := range recipients {
		rec, err := c.encodeRecipient(sharedSymKey, e, senderKp)
		if err != nil {
			return nil, err
		}
		encodedRecipients = append(encodedRecipients, *rec)
	}
	return encodedRecipients, nil
}

// encodeRecipient will encode the sharedKey (cek) with recipientKey
// by generating a new ephemeral key to be used by the recipient to decrypt the cek
func (c *Crypter) encodeRecipient(sharedSymKey, recipientKey *[chacha.KeySize]byte, senderKp keyPair) (*Recipient, error) { //nolint:lll
	// generate a random APU value (Agreement PartyUInfo: https://tools.ietf.org/html/rfc7518#section-4.6.1.2)
	apu := make([]byte, 64)
	_, err := randReader.Read(apu)
	if err != nil {
		return nil, err
	}

	// create a new ephemeral key for the recipient and return its APU
	kek, err := c.generateRecipientCEK(apu, senderKp.priv, recipientKey)
	if err != nil {
		return nil, err
	}

	// create a new (chacha20poly1035) cipher with this new key to encrypt the shared key (cek)
	crypter, err := createCipher(c.nonceSize, kek)
	if err != nil {
		return nil, err
	}

	// create a new nonce
	nonce := make([]byte, c.nonceSize)
	_, err = randReader.Read(nonce)
	if err != nil {
		return nil, err
	}

	// encrypt symmetric shared key cek using the recipient's ephemeral key
	kekOutput := crypter.Seal(nil, nonce, sharedSymKey[:], nil)

	tag := extractTag(kekOutput)
	sharedKeyCipher := extractCipherText(kekOutput)

	return c.buildRecipient(sharedKeyCipher, apu, nonce, tag, senderKp.pub, recipientKey)
}

// buildRecipient will build a proper JSON formatted Recipient
func (c *Crypter) buildRecipient(key string, apu, nonce []byte, tag string, senderPubKey, recipientKey *[chacha.KeySize]byte) (*Recipient, error) { //nolint:lll
	oid, err := encryptOID(recipientKey, []byte(base58.Encode(senderPubKey[:])))
	if err != nil {
		return nil, err
	}

	recipientHeaders := RecipientHeaders{
		APU: base64.RawURLEncoding.EncodeToString(apu),
		IV:  base64.RawURLEncoding.EncodeToString(nonce),
		Tag: tag,
		KID: base58.Encode(recipientKey[:]),
		OID: base64.RawURLEncoding.EncodeToString(oid),
	}

	recipient := &Recipient{
		EncryptedKey: key,
		Header:       recipientHeaders,
	}

	return recipient, nil
}

// generateRecipientCEK will generate an ephemeral symmetric key for the recipientKey to
// be used for encrypting the cek.
// it will return this new key along with the corresponding APU or an error if it fails.
func (c *Crypter) generateRecipientCEK(apu []byte, privKey, pubKey *[chacha.KeySize]byte) ([]byte, error) {
	// base64 encode the APU
	apuEncoded := make([]byte, base64.RawURLEncoding.EncodedLen(len(apu)))
	base64.RawURLEncoding.Encode(apuEncoded, apu)

	// generating Z is inspired by sodium_crypto_scalarmult()
	// https://github.com/gamringer/php-authcrypt/blob/master/src/Crypt.php#L80

	// with z being a basePoint of a curve25519
	z := &[chacha.KeySize]byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} //nolint:lll
	// do ScalarMult of the sender's private key with the recipient key to get a derived Z point
	// ( equivalent to derive an EC key )
	curve25519.ScalarMult(z, privKey, pubKey)

	// inspired by: github.com/square/go-jose/v3@v3.0.0-20190722231519-723929d55157/cipher/ecdh_es.go
	// -> DeriveECDHES() call

	// suppPubInfo is the encoded length of the recipient shared key output size in bits
	supPubInfo := make([]byte, 4)
	// since we're using chacha20poly1035 keys, keySize is known
	binary.BigEndian.PutUint32(supPubInfo, uint32(chacha.KeySize)*8)

	// get a Concat KDF stream for z, encryption algorithm, api, supPubInfo and empty supPrivInfo using sha256
	reader := josecipher.NewConcatKDF(crypto.SHA256, z[:], []byte(c.alg), apuEncoded, nil, supPubInfo, []byte{})

	// kek is the recipient specific encryption key used to encrypt the sharedSymKey
	kek := make([]byte, chacha.KeySize)

	// Read on the KDF will never fail
	_, err := reader.Read(kek)
	if err != nil {
		return nil, err
	}

	return kek, nil
}

// encryptOID will encrypt a msg (in the case of this package, it will be
// the sender's public key) using the recipient's pubKey,
// this is equivalent to libsodium's C function: crypto_box_seal()
// https://libsodium.gitbook.io/doc/public-key_cryptography/sealed_boxes#usage
// TODO add testing to ensure interoperability of encryptOID with libsodium's function above
//      the main difference between libsodium and below implementation is libsodium hides
//      the ephemeral key and the nonce creation from the caller while box.Seal requires these
//      to be prebuilt and passed as arguments.
// TODO replace 'OID' to 'SPK' recipient header which should represent the key in JWK encoded in a compact JWE format
func encryptOID(recipientPubKey *[chacha.KeySize]byte, msg []byte) ([]byte, error) {
	// generate ephemeral asymmetric keys
	epk, esk, err := box.GenerateKey(randReader)
	if err != nil {
		return nil, err
	}
	// generate an equivalent nonce to libsodium's (see link in comment above)
	nonce, err := generateLibsodiumNonce(epk[:], recipientPubKey[:])
	if err != nil {
		return nil, err
	}

	var out = make([]byte, len(epk))
	copy(out, epk[:])

	// now seal msg with the ephemeral key, nonce and recipientPubKey (which is the recipient's publicKey)
	return box.Seal(out, msg, nonce, recipientPubKey, esk), nil
}

// generateLibsodiumNonce will generate a nonce that is equivalent to libsodium's
// nonce format ie: black2b generation using concatenation of pub1 with pub2
func generateLibsodiumNonce(pub1, pub2 []byte) (*[24]byte, error) {
	var nonce [24]byte
	// generate an equivalent nonce to libsodium's
	nonceWriter, err := blake2b.New(24, nil)
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub1)
	if err != nil {
		return nil, err
	}
	_, err = nonceWriter.Write(pub2)
	if err != nil {
		return nil, err
	}

	nonceOut := nonceWriter.Sum(nil)
	copy(nonce[:], nonceOut)

	return &nonce, nil
}
