/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package kmssigner

import (
	"strings"

	"github.com/hyperledger/aries-framework-go/spi/crypto"
	"github.com/hyperledger/aries-framework-go/spi/kms"
)

const (
	p256Alg = "ES256"
	p384Alg = "ES384"
	p521Alg = "ES521"
	edAlg   = "EdDSA"
)

// KMSSigner implements JWS Signer interface using a KMS key handle and a crypto.Crypto instance.
type KMSSigner struct {
	KeyType   kms.KeyType
	KeyHandle interface{}
	Crypto    crypto.Crypto
	MultiMsg  bool
}

// Sign signs data using KMSSigner's KeyHandle.
func (s *KMSSigner) Sign(data []byte) ([]byte, error) {
	if s.MultiMsg {
		return s.Crypto.SignMulti(s.textToLines(string(data)), s.KeyHandle)
	}

	v, err := s.Crypto.Sign(data, s.KeyHandle)
	if err != nil {
		return nil, err
	}

	return v, nil
}

// Alg provides the JWA corresponding to the KMSSigner's KeyType.
func (s *KMSSigner) Alg() string {
	return KeyTypeToJWA(s.KeyType)
}

func (s *KMSSigner) textToLines(txt string) [][]byte {
	lines := strings.Split(txt, "\n")
	linesBytes := make([][]byte, 0, len(lines))

	for i := range lines {
		if strings.TrimSpace(lines[i]) != "" {
			linesBytes = append(linesBytes, []byte(lines[i]))
		}
	}

	return linesBytes
}

// KeyTypeToJWA provides the JWA corresponding to keyType.
func KeyTypeToJWA(keyType kms.KeyType) string {
	switch keyType {
	case kms.ECDSAP256IEEEP1363, kms.ECDSAP256DER:
		return p256Alg
	case kms.ECDSAP384IEEEP1363, kms.ECDSAP384DER:
		return p384Alg
	case kms.ECDSAP521IEEEP1363, kms.ECDSAP521DER:
		return p521Alg
	case kms.ED25519:
		return edAlg
	}

	return ""
}
