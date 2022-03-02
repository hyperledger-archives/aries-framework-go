/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

import spi "github.com/hyperledger/aries-framework-go/spi/storage"

// MACDigester represents a type that can compute MACs.
type MACDigester interface {
	ComputeMAC(data []byte, kh interface{}) ([]byte, error)
}

// MACCrypto is used for computing MACs.
type MACCrypto struct {
	kh          interface{}
	macDigester MACDigester
}

// ComputeMAC computes a MAC for data using a matching MAC primitive in kh.
func (m *MACCrypto) ComputeMAC(data []byte) ([]byte, error) {
	return m.macDigester.ComputeMAC(data, m.kh)
}

// NewMACCrypto returns a new instance of a MACCrypto.
func NewMACCrypto(kh interface{}, macDigester MACDigester) *MACCrypto {
	return &MACCrypto{
		kh:          kh,
		macDigester: macDigester,
	}
}

// PerfCrypto is used for computing all MAC and JWE encryption+KW in one call for performance optimization.
type PerfCrypto interface {
	BatchCrypto(req *BatchCryptoPayload, macKH, encKH interface{}) (*BatchCryptoPayload, error)
}

// BatchCryptoPayload struct represents a type that contains tags and document payloads for MACs and EDV encryption.
type BatchCryptoPayload struct {
	Prefix     string    `json:"Prefix,omitempty"`
	DocID      string    `json:"DocID"`
	DocTags    []spi.Tag `json:"DocTags,omitempty"`
	DocPayload string    `json:"DocPayload"`
}

// BatchCrypto is used for computing all EDV cryptos.
type BatchCrypto struct {
	macKH      interface{}
	kwKH       interface{}
	perfCrypto PerfCrypto
}

// ComputeCrypto computes all the MACs and EDV encryptions necessary by a KMS instance.
func (e *BatchCrypto) ComputeCrypto(req *BatchCryptoPayload) (*BatchCryptoPayload, error) {
	return e.perfCrypto.BatchCrypto(req, e.macKH, e.kwKH)
}

// NewBatchCrypto compute MACs and EDV encrypt payloads.
func NewBatchCrypto(macKH, kwKH interface{}, performanceCrypto PerfCrypto) *BatchCrypto {
	return &BatchCrypto{
		macKH:      macKH,
		kwKH:       kwKH,
		perfCrypto: performanceCrypto,
	}
}
