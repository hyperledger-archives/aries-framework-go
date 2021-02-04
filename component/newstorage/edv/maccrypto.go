/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package edv

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
