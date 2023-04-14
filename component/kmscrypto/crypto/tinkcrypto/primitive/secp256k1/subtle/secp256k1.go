/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package subtle

import (
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/btcec"

	secp256k1pb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/secp256k1_go_proto"
)

var errUnsupportedEncoding = errors.New("secp256k1: unsupported encoding")

// Secp256k1Signature is a struct holding the r and s values of an secp256k1 signature.
type Secp256k1Signature struct {
	R, S *big.Int
}

// NewSecp256K1Signature creates a new Secp256k1Signature instance.
func NewSecp256K1Signature(r, s *big.Int) *Secp256k1Signature {
	return &Secp256k1Signature{R: r, S: s}
}

// EncodeSecp256K1Signature converts the signature to the given encoding format.
func (sig *Secp256k1Signature) EncodeSecp256K1Signature(encoding, curveName string) ([]byte, error) {
	var (
		enc []byte
		err error
	)

	switch encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363.String():
		enc, err = ieeeP1363Encode(sig, curveName)
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER.String():
		enc, err = asn1encode(sig)
	default:
		err = errUnsupportedEncoding
	}

	if err != nil {
		return nil, fmt.Errorf("secp256k1: can't convert secp256k1 signature to %s encoding: %w", encoding, err)
	}

	return enc, nil
}

// DecodeSecp256K1Signature creates a new secp256k1 signature using the given byte slice.
// The function assumes that the byte slice is the concatenation of the BigEndian
// representation of two big integer r and s.
func DecodeSecp256K1Signature(encodedBytes []byte, encoding string) (*Secp256k1Signature, error) {
	var (
		sig *Secp256k1Signature
		err error
	)

	switch encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363.String():
		sig, err = ieeeP1363Decode(encodedBytes)
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER.String():
		sig, err = asn1decode(encodedBytes)
	default:
		err = errUnsupportedEncoding
	}

	if err != nil {
		return nil, fmt.Errorf("secp256k1: %w", err)
	}

	return sig, nil
}

// ValidateSecp256K1Params validates secp256k1 parameters.
// The hash's strength must not be weaker than the curve's strength.
// DER and IEEE_P1363 encodings are supported.
func ValidateSecp256K1Params(hashAlg, curve, encoding string) error {
	switch encoding {
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_DER.String():
	case secp256k1pb.Secp256K1SignatureEncoding_Bitcoin_IEEE_P1363.String():
	default:
		return errUnsupportedEncoding
	}

	switch curve {
	case secp256k1pb.BitcoinCurveType_SECP256K1.String():
		if hashAlg != "SHA256" {
			return errors.New("invalid hash type, expect SHA-256")
		}
	default:
		return fmt.Errorf("unsupported curve: %s", curve)
	}

	return nil
}

// GetCurve returns the curve object that corresponds to the given curve type.
// It returns null if the curve type is not supported.
func GetCurve(curve string) elliptic.Curve {
	switch curve {
	case secp256k1pb.BitcoinCurveType_SECP256K1.String():
		return btcec.S256()
	default:
		return nil
	}
}
