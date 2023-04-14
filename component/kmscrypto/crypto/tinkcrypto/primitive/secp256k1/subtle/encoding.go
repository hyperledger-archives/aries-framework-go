/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"
)

// asn1encode encodes the given ECDSA signature using ASN.1 encoding.
func asn1encode(sig *Secp256k1Signature) ([]byte, error) {
	ret, err := asn1.Marshal(*sig)
	if err != nil {
		return nil, fmt.Errorf("asn.1 encoding failed")
	}

	return ret, nil
}

var errAsn1Decoding = fmt.Errorf("asn.1 decoding failed")

// asn1decode verifies the given ECDSA signature and decodes it if it is valid.
// Since asn1.Unmarshal() doesn't do a strict verification on its input, it will
// accept signatures with trailing data. Therefore, we add an additional check to make sure
// that the input follows strict DER encoding: after unmarshalling the signature bytes,
// we marshal the obtained signature object again. Since DER encoding is deterministic,
// we expect that the obtained bytes would be equal to the input.
func asn1decode(b []byte) (*Secp256k1Signature, error) {
	sig := new(Secp256k1Signature)

	_, err := asn1.Unmarshal(b, sig) // der encoding does not work for Secp256k1 keys.
	if err != nil {
		return nil, errAsn1Decoding
	}

	// encode the signature again
	encoded, err := asn1.Marshal(*sig)
	if err != nil {
		return nil, errAsn1Decoding
	}

	if !bytes.Equal(b, encoded) {
		return nil, errAsn1Decoding
	}

	return sig, nil
}

func ieeeSignatureSize(curveName string) (int, error) {
	switch curveName {
	case btcec.S256().Params().Name:
		return 64, nil //nolint:gomnd
	default:
		return 0, fmt.Errorf("ieeeP1363 unsupported curve name: %q", curveName)
	}
}

func ieeeP1363Encode(sig *Secp256k1Signature, curveName string) ([]byte, error) {
	two := 2

	sigSize, err := ieeeSignatureSize(curveName)
	if err != nil {
		return nil, err
	}

	enc := make([]byte, sigSize)

	// sigR and sigS must be half the size of the signature. If not, we need to pad them with zeros.
	offset := 0
	if len(sig.R.Bytes()) < (sigSize / two) {
		offset += (sigSize / two) - len(sig.R.Bytes())
	}

	// Copy sigR after any zero-padding.
	copy(enc[offset:], sig.R.Bytes())

	// Skip the bytes of sigR.
	offset = sigSize / two
	if len(sig.S.Bytes()) < (sigSize / two) {
		offset += (sigSize / two) - len(sig.S.Bytes())
	}

	// Copy sigS after sigR and any zero-padding.
	copy(enc[offset:], sig.S.Bytes())

	return enc, nil
}

func ieeeP1363Decode(encodedBytes []byte) (*Secp256k1Signature, error) {
	if len(encodedBytes) == 0 || len(encodedBytes) > 132 || len(encodedBytes)%2 != 0 {
		return nil, fmt.Errorf("ecdsa: Invalid IEEE_P1363 encoded bytes")
	}

	r := new(big.Int).SetBytes(encodedBytes[:len(encodedBytes)/2])
	s := new(big.Int).SetBytes(encodedBytes[len(encodedBytes)/2:])

	return &Secp256k1Signature{R: r, S: s}, nil
}
