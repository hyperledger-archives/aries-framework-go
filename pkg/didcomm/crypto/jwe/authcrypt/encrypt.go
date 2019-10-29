/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package authcrypt

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/btcsuite/btcutil/base58"
	chacha "golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/poly1305"

	"github.com/hyperledger/aries-framework-go/pkg/internal/cryptoutil"
)

// Encrypt will JWE encode the payload argument for the sender and recipients
// Using (X)Chacha20 encryption algorithm and Poly1305 authenticator
// It will encrypt by fetching the sender's encryption key corresponding to senderVerKey and converting the list
// of recipientsVerKeys into a list of encryption keys
func (c *Crypter) Encrypt(payload, senderVerKey []byte, recipientsVerKeys [][]byte) ([]byte, error) { //nolint:funlen
	senderPubKey, err := c.getSenderPubEncKey(senderVerKey)
	if err != nil {
		return nil, err
	}

	headers := jweHeaders{
		Typ: "prs.hyperledger.aries-auth-message",
		Alg: "ECDH-SS+" + string(c.alg) + "KW",
		Enc: string(c.alg),
	}

	if len(recipientsVerKeys) == 0 {
		return nil, fmt.Errorf("failed to encrypt message: empty recipients")
	}
	chachaRecipients, err := c.convertRecipients(recipientsVerKeys)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}

	aad := buildAAD(chachaRecipients)
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
	cipher, err := createCipher(c.nonceSize, cek[:])
	if err != nil {
		return nil, err
	}

	// encrypt payload using generated nonce, payload and its AAD
	// the output is a []byte containing the cipherText + tag
	symOutput := cipher.Seal(nil, nonce, payload, []byte(pldAAD))

	tagEncoded := extractTag(symOutput)
	cipherTextEncoded := extractCipherText(symOutput)

	// now build, encode recipients and include the encrypted cek (with a recipient's ephemeral key)
	encRec, err := c.encodeRecipients(cek, chachaRecipients, senderPubKey)
	if err != nil {
		return nil, err
	}

	jwe, err := c.buildJWE(encHeaders, encRec, aadEncoded, nonceEncoded, tagEncoded, cipherTextEncoded)
	if err != nil {
		return nil, err
	}

	return jwe, nil
}

func (c *Crypter) getSenderPubEncKey(senderVerKey []byte) (*[chacha.KeySize]byte, error) {
	if len(senderVerKey) == 0 {
		return nil, fmt.Errorf("failed to encrypt message: empty sender key")
	}

	senderKey, err := c.kms.GetEncryptionKey(senderVerKey)
	if err != nil {
		return nil, err
	}
	senderPubKey := &[chacha.KeySize]byte{}
	copy(senderPubKey[:], senderKey)
	return senderPubKey, nil
}

// convertRecipients is a utility function that converts keys from signature keys ([][]byte type)
// into encryption keys ([]*[chacha.KeySize]byte type)
func (c *Crypter) convertRecipients(recipients [][]byte) ([]*[chacha.KeySize]byte, error) {
	var chachaRecipients []*[chacha.KeySize]byte

	for i, rVer := range recipients {
		if !cryptoutil.IsChachaKeyValid(rVer) {
			return nil, fmt.Errorf("%w - for recipient %d", cryptoutil.ErrInvalidKey, i+1)
		}
		rEnc, err := cryptoutil.PublicEd25519toCurve25519(rVer)
		if err != nil {
			return nil, err
		}

		chachaRec := new([chacha.KeySize]byte)
		copy(chachaRec[:], rEnc)
		chachaRecipients = append(chachaRecipients, chachaRec)
	}
	return chachaRecipients, nil
}

// extractTag is a utility function that extracts base64UrlEncoded tag sub-slice from symOutput returned by cipher.Seal
func extractTag(symOutput []byte) string {
	// symOutput has a length of len(clear msg) + poly1305.TagSize
	// fetch the tag from the tail of symOutput
	tag := symOutput[len(symOutput)-poly1305.TagSize:]

	// base64 encode the tag
	return base64.RawURLEncoding.EncodeToString(tag)
}

// extractCipherText is a utility function that extracts base64UrlEncoded cipherText sub-slice
// from symOutput returned by cipher.Seal
func extractCipherText(symOutput []byte) string {
	// fetch the cipherText from the head of symOutput (0:up to the trailing tag)
	cipherText := symOutput[0 : len(symOutput)-poly1305.TagSize]

	// base64 encode the cipherText
	return base64.RawURLEncoding.EncodeToString(cipherText)
}

// buildJWE builds the JSON object representing the JWE output of the encryption
// and returns its marshaled []byte representation
func (c *Crypter) buildJWE(headers string, recipients []Recipient, aad, iv, tag, cipherText string) ([]byte, error) { //nolint:lll
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

// buildAAD is a utility function to build the Additional Authentication Data for the AEAD (chach20poly1305) cipher.
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

// encodeRecipients is a utility function that will encrypt the cek (content encryption key) for each recipient
// and return a list of encoded recipient keys in a JWE compliant format ([]Recipient)
func (c *Crypter) encodeRecipients(cek *[chacha.KeySize]byte, recipients []*[chacha.KeySize]byte, senderPubKey *[chacha.KeySize]byte) ([]Recipient, error) { //nolint:lll
	var encodedRecipients []Recipient
	for _, e := range recipients {
		rec, err := c.encodeRecipient(cek, e, senderPubKey)
		if err != nil {
			return nil, err
		}
		encodedRecipients = append(encodedRecipients, *rec)
	}
	return encodedRecipients, nil
}

// encodeRecipient will encrypt the cek (content encryption key) with a recipientKey
// by generating a new ephemeral key to be used by the recipient to later decrypt it
// it returns a JWE compliant Recipient
func (c *Crypter) encodeRecipient(cek, recipientPubKey, senderPubKey *[chacha.KeySize]byte) (*Recipient, error) { //nolint:lll
	// generate a random APU value (Agreement PartyUInfo: https://tools.ietf.org/html/rfc7518#section-4.6.1.2)
	apu := make([]byte, 64)
	_, err := randReader.Read(apu)
	if err != nil {
		return nil, err
	}

	// derive an ephemeral key for the sender and recipient
	kek, err := c.kms.DeriveKEK([]byte(c.alg), apu, senderPubKey[:], recipientPubKey[:])
	if err != nil {
		return nil, err
	}

	sharedKeyCipher, tag, nonce, err := c.encryptCEK(kek, cek[:])
	if err != nil {
		return nil, err
	}

	spk, err := c.generateSPK(recipientPubKey, senderPubKey)
	if err != nil {
		return nil, err
	}

	return c.buildRecipient(sharedKeyCipher, apu, spk, nonce, tag, recipientPubKey)
}

// buildRecipient will build a proper JSON formatted and JWE compliant Recipient
func (c *Crypter) buildRecipient(key string, apu []byte, spkEncoded, nonceEncoded, tagEncoded string, recipientKey *[chacha.KeySize]byte) (*Recipient, error) { //nolint:lll
	recipientHeaders := RecipientHeaders{
		APU: base64.RawURLEncoding.EncodeToString(apu),
		IV:  nonceEncoded,
		Tag: tagEncoded,
		KID: base58.Encode(recipientKey[:]),
		SPK: spkEncoded,
	}

	recipient := &Recipient{
		EncryptedKey: key,
		Header:       recipientHeaders,
	}

	return recipient, nil
}

// encryptCEK will encrypt symKey with the given kek and a newly generated nonce
// returns:
// 		encrypted cipher of symKey
//		resulting tag of the encryption
//		generated nonce used by the encryption
//		error in case of failure
func (c *Crypter) encryptCEK(kek, cek []byte) (string, string, string, error) {
	cipher, err := createCipher(c.nonceSize, kek)
	if err != nil {
		return "", "", "", err
	}

	// create a new nonce
	nonce := make([]byte, c.nonceSize)
	_, err = randReader.Read(nonce)
	if err != nil {
		return "", "", "", err
	}

	// encrypt symmetric shared key using the key encryption key (kek)
	kekOutput := cipher.Seal(nil, nonce, cek, nil)

	symKeyCipherEncoded := extractCipherText(kekOutput)
	tagEncoded := extractTag(kekOutput)
	nonceEncoded := base64.RawURLEncoding.EncodeToString(nonce)
	return symKeyCipherEncoded, tagEncoded, nonceEncoded, nil
}
