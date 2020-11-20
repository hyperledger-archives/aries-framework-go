/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"encoding/base64"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
)

// wrapKeyReq serializable WrapKey request.
type wrapKeyReq struct {
	CEK       string       `json:"cek,omitempty"`
	APU       string       `json:"apu,omitempty"`
	APV       string       `json:"apv,omitempty"`
	RecPubKey publicKeyReq `json:"recpubkey,omitempty"`
	SenderKID string       `json:"senderkid,omitempty"`
}

// wrapKeyResp serializable WrapKey response.
type wrapKeyResp struct {
	WrappedKey recipientWrappedKeyReq `json:"wrappedKey,omitempty"`
}

// unwrapKeyReq serializable UnwrapKey request.
type unwrapKeyReq struct {
	WrappedKey recipientWrappedKeyReq `json:"wrappedKey,omitempty"`
	SenderKID  string                 `json:"senderkid,omitempty"`
}

// unwrapKeyResp serializable UnwrapKey response.
type unwrapKeyResp struct {
	Key string `json:"key,omitempty"`
}

// recipientWrappedKeyReq contains recipient key material required to unwrap CEK for HTTP requests.
type recipientWrappedKeyReq struct {
	KID          string       `json:"kid,omitempty"`
	EncryptedCEK string       `json:"encryptedcek,omitempty"`
	EPK          publicKeyReq `json:"epk,omitempty"`
	Alg          string       `json:"alg,omitempty"`
	APU          string       `json:"apu,omitempty"`
	APV          string       `json:"apv,omitempty"`
}

// publicKeyReq mainly to exchange EPK in RecipientWrappedKey for HTTP requests.
type publicKeyReq struct {
	KID   string `json:"kid,omitempty"`
	X     string `json:"x,omitempty"`
	Y     string `json:"y,omitempty"`
	Curve string `json:"curve,omitempty"`
	Type  string `json:"type,omitempty"`
}

// pubKeyToSerializableReq converts recPubKey into a serializable publicKeyReq.
func pubKeyToSerializableReq(recPubKey *crypto.PublicKey) publicKeyReq {
	return publicKeyReq{
		KID:   base64.URLEncoding.EncodeToString([]byte(recPubKey.KID)),
		X:     base64.URLEncoding.EncodeToString(recPubKey.X),
		Y:     base64.URLEncoding.EncodeToString(recPubKey.Y),
		Curve: base64.URLEncoding.EncodeToString([]byte(recPubKey.Curve)),
		Type:  base64.URLEncoding.EncodeToString([]byte(recPubKey.Type)),
	}
}

// wrappedKeyToSerializableReq converts wrappedKey into a serializable recipientWrappedKeyReq.
func wrappedKeyToSerializableReq(wrappedKey *crypto.RecipientWrappedKey) recipientWrappedKeyReq {
	return recipientWrappedKeyReq{
		KID:          base64.URLEncoding.EncodeToString([]byte(wrappedKey.KID)),
		EncryptedCEK: base64.URLEncoding.EncodeToString(wrappedKey.EncryptedCEK),
		EPK:          pubKeyToSerializableReq(&wrappedKey.EPK),
		Alg:          base64.URLEncoding.EncodeToString([]byte(wrappedKey.Alg)),
		APU:          base64.URLEncoding.EncodeToString(wrappedKey.APU),
		APV:          base64.URLEncoding.EncodeToString(wrappedKey.APV),
	}
}

// serializableReqToPubKey converts a serializable mRecPubKeyReq into *crypto.PublicKey.
func serializableReqToPubKey(mRecPubKeyReq *publicKeyReq) (*crypto.PublicKey, error) {
	kid, err := base64.URLEncoding.DecodeString(mRecPubKeyReq.KID)
	if err != nil {
		return nil, err
	}

	x, err := base64.URLEncoding.DecodeString(mRecPubKeyReq.X)
	if err != nil {
		return nil, err
	}

	y, err := base64.URLEncoding.DecodeString(mRecPubKeyReq.Y)
	if err != nil {
		return nil, err
	}

	curve, err := base64.URLEncoding.DecodeString(mRecPubKeyReq.Curve)
	if err != nil {
		return nil, err
	}

	typ, err := base64.URLEncoding.DecodeString(mRecPubKeyReq.Type)
	if err != nil {
		return nil, err
	}

	return &crypto.PublicKey{
		KID:   string(kid),
		X:     x,
		Y:     y,
		Curve: string(curve),
		Type:  string(typ),
	}, nil
}

// serializableToWrappedKey converts a serializable mWKReq into *crypto.RecipientWrappedKey.
func serializableToWrappedKey(mWKReq *recipientWrappedKeyReq) (*crypto.RecipientWrappedKey, error) {
	kid, err := base64.URLEncoding.DecodeString(mWKReq.KID)
	if err != nil {
		return nil, err
	}

	alg, err := base64.URLEncoding.DecodeString(mWKReq.Alg)
	if err != nil {
		return nil, err
	}

	apu, err := base64.URLEncoding.DecodeString(mWKReq.APU)
	if err != nil {
		return nil, err
	}

	apv, err := base64.URLEncoding.DecodeString(mWKReq.APV)
	if err != nil {
		return nil, err
	}

	epk, err := serializableReqToPubKey(&mWKReq.EPK)
	if err != nil {
		return nil, err
	}

	enc, err := base64.URLEncoding.DecodeString(mWKReq.EncryptedCEK)
	if err != nil {
		return nil, err
	}

	return &crypto.RecipientWrappedKey{
		KID:          string(kid),
		EncryptedCEK: enc,
		EPK:          *epk,
		Alg:          string(alg),
		APU:          apu,
		APV:          apv,
	}, nil
}
