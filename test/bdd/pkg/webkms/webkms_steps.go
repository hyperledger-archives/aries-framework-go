/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/cucumber/godog"
	"github.com/teserakt-io/golang-ed25519/extra25519"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/webkms"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	defaultKeySize     = sha256.Size
	curve25519KeySize  = 32
	cryptoBoxNonceSize = 24
)

// SDKSteps is steps for crypto operations.
type SDKSteps struct {
	bddContext  *context.BDDContext
	keyIDs      map[string]string
	pubKeyBytes map[string][]byte
	signatures  map[string][]byte
	ciphertexts map[string][]byte
	nonces      map[string][]byte
	plaintexts  map[string][]byte
	macs        map[string][]byte
	cekKeys     map[string][]byte
	wrappedKeys map[string]*crypto.RecipientWrappedKey
}

// NewCryptoSDKSteps creates steps for crypto operations.
func NewCryptoSDKSteps() *SDKSteps {
	return &SDKSteps{
		keyIDs:      map[string]string{},
		pubKeyBytes: map[string][]byte{},
		signatures:  map[string][]byte{},
		ciphertexts: map[string][]byte{},
		nonces:      map[string][]byte{},
		plaintexts:  map[string][]byte{},
		macs:        map[string][]byte{},
		cekKeys:     map[string][]byte{},
		wrappedKeys: map[string]*crypto.RecipientWrappedKey{},
	}
}

// SetContext is called before every scenario is run with a fresh new context.
func (c *SDKSteps) SetContext(s *context.BDDContext) {
	c.bddContext = s
}

// RegisterSteps registers Crypto steps.
func (c *SDKSteps) RegisterSteps(s *godog.Suite) {
	// create/export/import key steps
	s.Step(`^"([^"]*)" create "([^"]*)" key$`, c.createKey)
	s.Step(`^"([^"]*)" export public key$`, c.exportPubKey)
	s.Step(`^"([^"]*)" create and export "([^"]*)" key$`,
		c.createAndExportKey)
	s.Step(`^"([^"]*)" import a private key with ID "([^"]*)"$`,
		c.importKey)

	// sign/verify message steps
	s.Step(`^"([^"]*)" sign "([^"]*)"$`, c.signMessage)
	s.Step(`^"([^"]*)" verifies signature for "([^"]*)"$`, c.verifySignature)

	// state checking steps
	s.Step(`^"([^"]*)" gets non-empty key id$`, c.checkNonEmptykeyID)
	s.Step(`^"([^"]*)" gets non-empty public key bytes$`, c.checkNonEmptyPubKeyBytes)
	s.Step(`^"([^"]*)" gets non-empty signature$`, c.checkNonEmptySignature)
	s.Step(`^"([^"]*)" gets non-empty MAC$`, c.checkNonEmptyMAC)
	s.Step(`^"([^"]*)" gets non-empty ciphertext`, c.checkNonEmptyCiphertext)
	s.Step(`^"([^"]*)" gets non-empty nonce$`, c.checkNonEmptyNonce)
	s.Step(`^"([^"]*)" gets non-empty wrapped key$`, c.checkNonEmptyWrappedKey)
	s.Step(`^"([^"]*)" gets the same CEK as "([^"]*)"$`, c.checkHasSameCEK)
	s.Step(`^"([^"]*)" gets plaintext with value "([^"]*)"$`, c.checkPlaintext)

	// encrypt/decrypt message steps
	s.Step(`^"([^"]*)" encrypt "([^"]*)" with "([^"]*)" aad$`, c.encryptMessage)
	s.Step(`^"([^"]*)" decrypt ciphertext with "([^"]*)" aad$`, c.decryptCipher)

	// compute/verify MAC steps
	s.Step(`^"([^"]*)" compute MAC for "([^"]*)"$`, c.computeMAC)
	s.Step(`^"([^"]*)" verifies MAC for "([^"]*)"$`, c.verifyMAC)

	// wrap/unwrap key steps
	s.Step(`^"([^"]*)" wrap CEK with "([^"]*)" public key$`, c.wrapKey)
	s.Step(`^"([^"]*)" unwrap wrapped key from "([^"]*)"$`, c.unwrapKey)
	s.Step(`^"([^"]*)" wrap CEK with "([^"]*)" public key and with sender key$`, c.wrapKeyWithSenderKey)
	s.Step(`^"([^"]*)" unwrap wrapped key from "([^"]*)" with sender key$`, c.unwrapKeyWithSenderKey)

	// CryptoBox steps
	s.Step(`^"([^"]*)" easy "([^"]*)" for "([^"]*)"$`, c.easyPayload)
	s.Step(`^"([^"]*)" easyOpen ciphertext from "([^"]*)"$`, c.easyOpen)
	s.Step(`^"([^"]*)" has sealed "([^"]*)" for "([^"]*)"$`, c.sealPayloadForRecipient)
	s.Step(`^"([^"]*)" sealOpen ciphertext from "([^"]*)"$`, c.sealOpen)
}

func (c *SDKSteps) createKey(agentID, keyType string) error {
	agent := c.bddContext.AgentCtx[agentID]

	keyID, _, err := agent.KMS().Create(kms.KeyType(keyType))
	if err != nil {
		return err
	}

	c.keyIDs[agentID] = keyID

	return nil
}

func (c *SDKSteps) exportPubKey(agentID string) error {
	agent := c.bddContext.AgentCtx[agentID]

	keyBytes, err := agent.KMS().ExportPubKeyBytes(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	c.pubKeyBytes[agentID] = keyBytes

	return nil
}

func (c *SDKSteps) createAndExportKey(agentID, keyType string) error {
	agent := c.bddContext.AgentCtx[agentID]

	keyID, keyBytes, err := agent.KMS().CreateAndExportPubKeyBytes(kms.KeyType(keyType))
	if err != nil {
		return err
	}

	c.keyIDs[agentID] = keyID
	c.pubKeyBytes[agentID] = keyBytes

	return nil
}

func (c *SDKSteps) importKey(agentID, keyID string) error {
	agent := c.bddContext.AgentCtx[agentID]

	_, pk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	newkeyID, _, err := agent.KMS().ImportPrivateKey(pk, kms.ED25519Type, kms.WithKeyID(keyID))
	if err != nil {
		return err
	}

	c.keyIDs[agentID] = newkeyID

	return nil
}

func (c *SDKSteps) signMessage(agentID, message string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	signature, err := agent.Crypto().Sign([]byte(message), kh)
	if err != nil {
		return err
	}

	c.signatures[agentID] = signature

	return nil
}

func (c *SDKSteps) verifySignature(agentID, message string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	return agent.Crypto().Verify(c.signatures[agentID], []byte(message), kh)
}

func (c *SDKSteps) encryptMessage(agentID, message, aad string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	ciphertext, nonce, err := agent.Crypto().Encrypt([]byte(message), []byte(aad), kh)
	if err != nil {
		return err
	}

	c.ciphertexts[agentID] = ciphertext
	c.nonces[agentID] = nonce

	return nil
}

func (c *SDKSteps) decryptCipher(agentID, aad string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	plaintext, err := agent.Crypto().Decrypt(c.ciphertexts[agentID], []byte(aad), c.nonces[agentID], kh)
	if err != nil {
		return err
	}

	c.plaintexts[agentID] = plaintext

	return nil
}

func (c *SDKSteps) computeMAC(agentID, message string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	mac, err := agent.Crypto().ComputeMAC([]byte(message), kh)
	if err != nil {
		return err
	}

	c.macs[agentID] = mac

	return nil
}

func (c *SDKSteps) verifyMAC(agentID, message string) error {
	agent := c.bddContext.AgentCtx[agentID]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	return agent.Crypto().VerifyMAC(c.macs[agentID], []byte(message), kh)
}

func (c *SDKSteps) wrapKey(agentID, recipient string) error {
	agent := c.bddContext.AgentCtx[agentID]

	recipientPubKey, err := parsePublicKey(c.pubKeyBytes[recipient])
	if err != nil {
		return err
	}

	cek := generateRandomBytes(defaultKeySize)

	wrappedKey, err := agent.Crypto().WrapKey(
		cek, []byte("sender"), []byte("recipient"),
		recipientPubKey,
	)
	if err != nil {
		return err
	}

	c.cekKeys[agentID] = cek
	c.wrappedKeys[agentID] = wrappedKey

	return nil
}

func (c *SDKSteps) unwrapKey(agentID, sender string) error {
	agent := c.bddContext.AgentCtx[agentID]
	wrappedKey := c.wrappedKeys[sender]

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	unwrappedKey, err := agent.Crypto().UnwrapKey(wrappedKey, kh)
	if err != nil {
		return err
	}

	c.cekKeys[agentID] = unwrappedKey

	return nil
}

func (c *SDKSteps) wrapKeyWithSenderKey(agentID, recipient string) error {
	agent := c.bddContext.AgentCtx[agentID]

	recipientPubKey, err := parsePublicKey(c.pubKeyBytes[recipient])
	if err != nil {
		return err
	}

	cek := generateRandomBytes(defaultKeySize)

	wrappedKey, err := agent.Crypto().WrapKey(
		cek, []byte("sender"), []byte("recipient"),
		recipientPubKey,
		crypto.WithSender(c.keyIDs[agentID]),
	)
	if err != nil {
		return err
	}

	c.cekKeys[agentID] = cek
	c.wrappedKeys[agentID] = wrappedKey

	return nil
}

func (c *SDKSteps) unwrapKeyWithSenderKey(agentID, sender string) error {
	agent := c.bddContext.AgentCtx[agentID]
	wrappedKey := c.wrappedKeys[sender]

	senderPubKey, err := parsePublicKey(c.pubKeyBytes[sender])
	if err != nil {
		return err
	}

	kh, err := agent.KMS().Get(c.keyIDs[agentID])
	if err != nil {
		return err
	}

	unwrappedKey, err := agent.Crypto().UnwrapKey(wrappedKey, kh, crypto.WithSender(senderPubKey))
	if err != nil {
		return err
	}

	c.cekKeys[agentID] = unwrappedKey

	return nil
}

func (c *SDKSteps) easyPayload(agentID, payload, recipient string) error {
	agent := c.bddContext.AgentCtx[agentID]

	cryptoBox, err := webkms.NewCryptoBox(agent.KMS())
	if err != nil {
		return fmt.Errorf("crypto box create failed: %w", err)
	}

	recPubCurve25519, err := publicEd25519toCurve25519(c.pubKeyBytes[recipient])
	if err != nil {
		return err
	}

	nonce := generateNonceForCryptoBox()

	ciphertext, err := cryptoBox.Easy([]byte(payload), nonce, recPubCurve25519, c.keyIDs[agentID])
	if err != nil {
		return err
	}

	c.ciphertexts[agentID] = ciphertext
	c.nonces[agentID] = nonce

	return nil
}

func (c *SDKSteps) easyOpen(agentID, sender string) error {
	agent := c.bddContext.AgentCtx[agentID]

	cryptoBox, err := webkms.NewCryptoBox(agent.KMS())
	if err != nil {
		return fmt.Errorf("crypto box create failed: %w", err)
	}

	theirPubCurve25519, err := publicEd25519toCurve25519(c.pubKeyBytes[sender])
	if err != nil {
		return err
	}

	plaintext, err := cryptoBox.EasyOpen(
		c.ciphertexts[sender], c.nonces[sender], theirPubCurve25519, c.pubKeyBytes[agentID])
	if err != nil {
		return err
	}

	c.plaintexts[agentID] = plaintext

	return nil
}

func (c *SDKSteps) sealPayloadForRecipient(agentID, payload, recipient string) error {
	agent := c.bddContext.AgentCtx[agentID]

	cryptoBox, err := webkms.NewCryptoBox(agent.KMS())
	if err != nil {
		return fmt.Errorf("crypto box create failed: %w", err)
	}

	recPubCurve25519, err := publicEd25519toCurve25519(c.pubKeyBytes[recipient])
	if err != nil {
		return err
	}

	ciphertext, err := cryptoBox.Seal([]byte(payload), recPubCurve25519, rand.Reader)
	if err != nil {
		return err
	}

	c.ciphertexts[agentID] = ciphertext

	return nil
}

func (c *SDKSteps) sealOpen(agentID, sender string) error {
	agent := c.bddContext.AgentCtx[agentID]

	cryptoBox, err := webkms.NewCryptoBox(agent.KMS())
	if err != nil {
		return fmt.Errorf("crypto box create failed: %w", err)
	}

	plaintext, err := cryptoBox.SealOpen(c.ciphertexts[sender], c.pubKeyBytes[agentID])
	if err != nil {
		return err
	}

	c.plaintexts[agentID] = plaintext

	return nil
}

func (c *SDKSteps) checkNonEmptykeyID(agentID string) error {
	if c.keyIDs[agentID] == "" {
		return fmt.Errorf("expected keyID to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptyPubKeyBytes(agentID string) error {
	if c.pubKeyBytes[agentID] == nil {
		return fmt.Errorf("expected public key bytes to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptySignature(agentID string) error {
	if c.signatures[agentID] == nil {
		return fmt.Errorf("expected signature to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptyMAC(agentID string) error {
	if c.macs[agentID] == nil {
		return fmt.Errorf("expected MAC to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptyCiphertext(agentID string) error {
	if c.ciphertexts[agentID] == nil {
		return fmt.Errorf("expected ciphertext to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptyNonce(agentID string) error {
	if c.nonces[agentID] == nil {
		return fmt.Errorf("expected nonce to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkNonEmptyWrappedKey(agentID string) error {
	if c.wrappedKeys[agentID] == nil {
		return fmt.Errorf("expected wrapped key to be non-empty")
	}

	return nil
}

func (c *SDKSteps) checkHasSameCEK(agentID, sender string) error {
	if !bytes.Equal(c.cekKeys[agentID], c.cekKeys[sender]) {
		return fmt.Errorf("expected CEKs to be equivalent")
	}

	return nil
}

func (c *SDKSteps) checkPlaintext(agentID, expectedValue string) error {
	if string(c.plaintexts[agentID]) != expectedValue {
		return fmt.Errorf("expected plaintext to be equal to '%s' but got '%s'", expectedValue, string(c.plaintexts[agentID]))
	}

	return nil
}

func parsePublicKey(rawBytes []byte) (*crypto.PublicKey, error) {
	// depending on key type, raw bytes might not represent publicKey structure
	var k crypto.PublicKey
	if err := json.Unmarshal(rawBytes, &k); err != nil {
		return nil, fmt.Errorf("public key parsing failed: %w", err)
	}

	return &k, nil
}

func generateRandomBytes(n uint32) []byte {
	buf := make([]byte, n)

	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}

	return buf
}

func generateNonceForCryptoBox() []byte {
	return generateRandomBytes(cryptoBoxNonceSize)
}

func publicEd25519toCurve25519(pub []byte) ([]byte, error) {
	if len(pub) == 0 {
		return nil, errors.New("public key is nil")
	}

	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%d-byte key size is invalid", len(pub))
	}

	pkOut := new([curve25519KeySize]byte)
	pKIn := new([curve25519KeySize]byte)
	copy(pKIn[:], pub)

	success := extra25519.PublicKeyToCurve25519(pkOut, pKIn)
	if !success {
		return nil, errors.New("error converting public key")
	}

	return pkOut[:], nil
}
