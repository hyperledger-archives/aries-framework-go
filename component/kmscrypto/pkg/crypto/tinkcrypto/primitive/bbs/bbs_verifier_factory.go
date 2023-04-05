/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bbs

import (
	"errors"
	"fmt"

	"github.com/google/tink/go/core/cryptofmt"
	"github.com/google/tink/go/core/primitiveset"
	"github.com/google/tink/go/core/registry"
	"github.com/google/tink/go/keyset"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	bbsapi "github.com/hyperledger/aries-framework-go/component/kmscrypto/pkg/crypto/tinkcrypto/primitive/bbs/api"
)

// NewVerifier returns a Verifier primitive from the given keyset handle.
func NewVerifier(h *keyset.Handle) (bbsapi.Verifier, error) {
	return NewVerifierWithKeyManager(h, nil)
}

// NewVerifierWithKeyManager returns a Verifier primitive from the given keyset handle and custom key manager.
func NewVerifierWithKeyManager(h *keyset.Handle, km registry.KeyManager) (bbsapi.Verifier, error) {
	ps, err := h.PrimitivesWithKeyManager(km)
	if err != nil {
		return nil, fmt.Errorf("bbs_verifier_factory: cannot obtain primitive set: %w", err)
	}

	return newWrappedVerifier(ps)
}

var (
	errInvalidSignature      = errors.New("bbs_verifier_factory: invalid signature")
	errInvalidSignatureProof = errors.New("bbs_verifier_factory: invalid signature proof")
	errInvalidPrimitive      = errors.New("bbs_verifier_factory: not a Verifier primitive")
)

// wrappedVerifier is a BBS Verifier implementation that uses the underlying primitive set for BBS signature
// verification and proof creation/verification.
type wrappedVerifier struct {
	ps *primitiveset.PrimitiveSet
}

func newWrappedVerifier(ps *primitiveset.PrimitiveSet) (bbsapi.Verifier, error) {
	if _, ok := (ps.Primary.Primitive).(bbsapi.Verifier); !ok {
		return nil, errInvalidPrimitive
	}

	for _, primitives := range ps.Entries {
		for _, p := range primitives {
			if _, ok := (p.Primitive).(bbsapi.Verifier); !ok {
				return nil, errInvalidPrimitive
			}
		}
	}

	ret := new(wrappedVerifier)
	ret.ps = ps

	return ret, nil
}

func (wv *wrappedVerifier) fetchNonRawKeyEntries(signature []byte) ([]byte, []byte, error) {
	prefixSize := cryptofmt.NonRawPrefixSize
	if len(signature) < prefixSize {
		return nil, nil, errInvalidSignature
	}

	prefix := signature[:prefixSize]
	signatureNoPrefix := signature[prefixSize:]

	return signatureNoPrefix, prefix, nil
}

func buildPrefixedMsgToSign(messages [][]byte, entry *primitiveset.Entry) [][]byte {
	if entry.PrefixType == tinkpb.OutputPrefixType_LEGACY {
		return append(messages, []byte{cryptofmt.LegacyStartByte})
	}

	return messages
}

func toBBSVerifier(v interface{}) (bbsapi.Verifier, error) {
	verifier, ok := v.(bbsapi.Verifier)
	if !ok {
		return nil, errInvalidPrimitive
	}

	return verifier, nil
}

// Verify checks whether the given signature is a valid signature of the given messages.
func (wv *wrappedVerifier) Verify(messages [][]byte, signature []byte) error {
	signatureNoPrefix, prefix, err := wv.fetchNonRawKeyEntries(signature)
	if err != nil {
		return err
	}

	// try non-raw keys
	entries, err := wv.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var verifier bbsapi.Verifier

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return err
			}

			dataToSign := buildPrefixedMsgToSign(messages, entries[i])
			if err = verifier.Verify(dataToSign, signatureNoPrefix); err == nil {
				return nil
			}
		}
	}

	// try raw keys
	entries, err = wv.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var verifier bbsapi.Verifier

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return err
			}

			if err = verifier.Verify(messages, signature); err == nil {
				return nil
			}
		}
	}

	return errInvalidSignature
}

// VerifyProof will verify a BBS+ signature proof (generated by a Verifier's DeriveProof() call) of the given messages.
func (wv *wrappedVerifier) VerifyProof(messages [][]byte, proof, nonce []byte) error {
	proofNoPrefix, prefix, err := wv.fetchNonRawKeyEntries(proof)
	if err != nil {
		return err
	}

	// try non-raw keys
	entries, err := wv.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var verifier bbsapi.Verifier

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return err
			}

			msgsToSign := buildPrefixedMsgToSign(messages, entries[i])
			if err = verifier.VerifyProof(msgsToSign, proofNoPrefix, nonce); err == nil {
				return nil
			}
		}
	}

	// try raw keys
	entries, err = wv.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var verifier bbsapi.Verifier

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return err
			}

			if err = verifier.VerifyProof(messages, proof, nonce); err == nil {
				return nil
			}
		}
	}

	return errInvalidSignatureProof
}

// DeriveProof will create a BBS+ signature proof for a list of revealed messages using BBS signature (generated by a
// Signer's Sign() call).
func (wv *wrappedVerifier) DeriveProof(messages [][]byte, signature, nonce []byte,
	revealedIndexes []int) ([]byte, error) {
	signatureNoPrefix, prefix, err := wv.fetchNonRawKeyEntries(signature)
	if err != nil {
		return nil, err
	}

	// try non-raw keys
	entries, err := wv.ps.EntriesForPrefix(string(prefix))
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var (
				verifier bbsapi.Verifier
				proof    []byte
			)

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return nil, err
			}

			msgsToSign := buildPrefixedMsgToSign(messages, entries[i])
			if proof, err = verifier.DeriveProof(msgsToSign, signatureNoPrefix, nonce, revealedIndexes); err == nil {
				ret := make([]byte, 0, len(entries[i].Prefix)+len(proof))
				ret = append(ret, entries[i].Prefix...)
				ret = append(ret, proof...)

				return ret, nil
			}
		}
	}

	// try raw keys
	entries, err = wv.ps.RawEntries()
	if err == nil {
		for i := 0; i < len(entries); i++ {
			var (
				verifier bbsapi.Verifier
				proof    []byte
			)

			verifier, err = toBBSVerifier(entries[i].Primitive)
			if err != nil {
				return nil, err
			}

			if proof, err = verifier.DeriveProof(messages, signature, nonce, revealedIndexes); err == nil {
				ret := make([]byte, 0, len(entries[i].Prefix)+len(proof))
				ret = append(ret, entries[i].Prefix...)
				ret = append(ret, proof...)

				return ret, nil
			}
		}
	}

	return nil, errInvalidSignatureProof
}
