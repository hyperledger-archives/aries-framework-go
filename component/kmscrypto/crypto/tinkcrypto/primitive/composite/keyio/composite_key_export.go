/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package keyio

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/golang/protobuf/proto"
	tinkaead "github.com/google/tink/go/aead"
	hybrid "github.com/google/tink/go/hybrid/subtle"
	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"

	"github.com/hyperledger/aries-framework-go/spi/kms"

	cryptoapi "github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/aead"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

// Package keyio supports exporting of Composite keys (aka Write) and converting the public key part of the a composite
// key (aka PublicKeyToHandle to be used as a valid Tink key)

const (
	nistPECDHKWPublicKeyTypeURL   = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPublicKey"
	x25519ECDHKWPublicKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPublicKey"
	nistPECDHKWPrivateKeyTypeURL  = "type.hyperledger.org/hyperledger.aries.crypto.tink.NistPEcdhKwPrivateKey"
	x25519ECDHKWPrivateKeyTypeURL = "type.hyperledger.org/hyperledger.aries.crypto.tink.X25519EcdhKwPrivateKey"
)

//nolint:gochecknoglobals
var ecdhKeyTypes = map[string]kms.KeyType{
	"NIST_P256": kms.NISTP256ECDHKWType,
	"NIST_P384": kms.NISTP384ECDHKWType,
	"NIST_P521": kms.NISTP521ECDHKWType,
}

// PubKeyWriter will write the raw bytes of a Tink KeySet's primary public key. The raw bytes are a marshaled
// composite.VerificationMethod type.
// The keyset must have a keyURL value equal to either one of the public key URLs:
//   - `nistPECDHKWPublicKeyTypeURL`
//   - `x25519ECDHKWPublicKeyTypeURL`
//
// constants of ecdh package.
// Note: This writer should be used only for ECDH public key exports. Other export of public keys should be
//
//	called via localkms package.
type PubKeyWriter struct {
	// KeyType is Key Type of the written key. It's needed as Write() is an interface function and can't return it.
	KeyType kms.KeyType
	w       io.Writer
}

// NewWriter creates a new PubKeyWriter instance.
func NewWriter(w io.Writer) *PubKeyWriter {
	return &PubKeyWriter{
		w: w,
	}
}

// Write writes the public keyset to the underlying w.Writer.
func (p *PubKeyWriter) Write(ks *tinkpb.Keyset) error {
	return p.write(ks)
}

// WriteEncrypted writes the encrypted keyset to the underlying w.Writer.
func (p *PubKeyWriter) WriteEncrypted(_ *tinkpb.EncryptedKeyset) error {
	return fmt.Errorf("write encrypted function not supported")
}

func (p *PubKeyWriter) write(msg *tinkpb.Keyset) error {
	ks := msg.Key
	primaryKID := msg.PrimaryKeyId
	created := false

	var err error

	for _, key := range ks {
		if key.KeyId == primaryKID && key.Status == tinkpb.KeyStatusType_ENABLED {
			created, err = p.writePubKey(key)
			if err != nil {
				return err
			}

			break
		}
	}

	if !created {
		return fmt.Errorf("key not written")
	}

	return nil
}

func (p *PubKeyWriter) writePubKey(key *tinkpb.Keyset_Key) (bool, error) {
	pubKey, kt, err := protoToCompositeKey(key.KeyData)
	if err != nil {
		return false, err
	}

	mPubKey, err := json.Marshal(pubKey)
	if err != nil {
		return false, err
	}

	n, err := p.w.Write(mPubKey)
	if err != nil {
		return false, err
	}

	p.KeyType = kt

	return n > 0, nil
}

func protoToCompositeKey(keyData *tinkpb.KeyData) (*cryptoapi.PublicKey, kms.KeyType, error) {
	var (
		cKey compositeKeyGetter
		err  error
	)

	switch keyData.TypeUrl {
	case nistPECDHKWPublicKeyTypeURL, x25519ECDHKWPublicKeyTypeURL:
		cKey, err = newECDHKey(keyData.Value)
		if err != nil {
			return nil, "", err
		}
	default:
		return nil, "", fmt.Errorf("can't export key with keyURL:%s", keyData.TypeUrl)
	}

	return buildKey(cKey)
}

func buildKey(c compositeKeyGetter) (*cryptoapi.PublicKey, kms.KeyType, error) {
	curveName := c.curveName()
	keyTypeName := c.keyType()

	return buildCompositeKey(c.kid(), keyTypeName, curveName, c.x(), c.y())
}

func buildCompositeKey(kid, keyType, curve string, x, y []byte) (*cryptoapi.PublicKey, kms.KeyType, error) {
	var kt kms.KeyType

	// validate keyType and curve
	switch keyType {
	case ecdhpb.KeyType_EC.String():
		// validate NIST P curves
		_, err := hybrid.GetCurve(curve)
		if err != nil {
			return nil, "", fmt.Errorf("undefined EC curve: %w", err)
		}

		kt = ecdhKeyTypes[curve]
	case ecdhpb.KeyType_OKP.String():
		if curve != commonpb.EllipticCurveType_CURVE25519.String() {
			return nil, "", fmt.Errorf("invalid OKP curve: %s", curve)
		}

		// use JWK curve name when exporting the key.
		curve = "X25519"
		kt = kms.X25519ECDHKWType
	default:
		return nil, "", fmt.Errorf("invalid keyType: %s", keyType)
	}

	return &cryptoapi.PublicKey{
		KID:   kid,
		Type:  keyType,
		Curve: curve,
		X:     x,
		Y:     y,
	}, kt, nil
}

type compositeKeyGetter interface {
	kid() string
	curveName() string
	keyType() string
	x() []byte
	y() []byte
}

type ecdhKey struct {
	protoKey *ecdhpb.EcdhAeadPublicKey
}

func newECDHKey(mKey []byte) (compositeKeyGetter, error) {
	pubKeyProto := new(ecdhpb.EcdhAeadPublicKey)

	err := proto.Unmarshal(mKey, pubKeyProto)
	if err != nil {
		return nil, err
	}

	return &ecdhKey{protoKey: pubKeyProto}, nil
}

func (e *ecdhKey) kid() string {
	return e.protoKey.KID
}

func (e *ecdhKey) curveName() string {
	return e.protoKey.Params.KwParams.CurveType.String()
}

func (e *ecdhKey) keyType() string {
	return e.protoKey.Params.KwParams.KeyType.String()
}

func (e *ecdhKey) x() []byte {
	return e.protoKey.X
}

func (e *ecdhKey) y() []byte {
	return e.protoKey.Y
}

// ExtractPrimaryPublicKey is a utility function that will extract the main public key from *keyset.Handle kh.
func ExtractPrimaryPublicKey(kh *keyset.Handle) (*cryptoapi.PublicKey, error) {
	keyBytes, err := writePubKeyFromKeyHandle(kh)
	if err != nil {
		return nil, fmt.Errorf("extractPrimaryPublicKey: failed to get public key content: %w", err)
	}

	ecPubKey := new(cryptoapi.PublicKey)

	err = json.Unmarshal(keyBytes, ecPubKey)
	if err != nil {
		return nil, fmt.Errorf("extractPrimaryPublicKey: unmarshal key failed: %w", err)
	}

	return ecPubKey, nil
}

func writePubKeyFromKeyHandle(handle *keyset.Handle) ([]byte, error) {
	pubKH, err := handle.Public()
	if err != nil {
		if strings.HasSuffix(err.Error(), "keyset contains a non-private key") {
			pubKH = handle
		} else {
			return nil, err
		}
	}

	buf := new(bytes.Buffer)
	pubKeyWriter := NewWriter(buf)

	err = pubKH.WriteWithNoSecrets(pubKeyWriter)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// PublicKeyToKeysetHandle converts pubKey into a *keyset.Handle where pubKey could be either a sender or a
// recipient key. The resulting handle cannot be directly used for primitive execution as the cek is not set. This
// function serves as a helper to get a senderKH to be used as an option for ECDH execution (for ECDH-1PU/authcrypt).
// The keyset handle will be set with either AES256-GCM, AES128CBC+SHA256, AES192CBC+SHA384, AES256CBC+SHA384 or
// AES256CBC+SHA512 AEAD key template for content encryption. With:
// - pubKey the public key to convert.
// - aeadAlg the content encryption algorithm to use along the ECDH primitive.
func PublicKeyToKeysetHandle(pubKey *cryptoapi.PublicKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	// validate curve
	cp, err := getCurveProto(pubKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to convert curve string to proto: %w", err)
	}

	kt, err := getKeyType(pubKey.Type)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to convert key type to proto: %w", err)
	}

	encT, keyURL, err := keyTemplateAndURL(cp, aeadAlg, true)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: %w", err)
	}

	protoKey := &ecdhpb.EcdhAeadPublicKey{
		Version: 0,
		Params: &ecdhpb.EcdhAeadParams{
			KwParams: &ecdhpb.EcdhKwParams{
				CurveType: cp,
				KeyType:   kt,
			},
			EncParams: &ecdhpb.EcdhAeadEncParams{
				AeadEnc: encT,
			},
			EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
		},
		KID: pubKey.KID,
		X:   pubKey.X,
		Y:   pubKey.Y,
	}

	marshalledKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to marshal proto: %w", err)
	}

	ks := newKeySet(keyURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PUBLIC)

	memReader := &keyset.MemReaderWriter{Keyset: ks}

	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("publicKeyToKeysetHandle: failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

// PrivateKeyToKeysetHandle converts privKey into a *keyset.Handle where privKey could be either a sender or a
// recipient key. The resulting handle cannot be directly used for primitive execution as the cek is not set. This
// function serves as a helper to get a senderKH to be used as an option for ECDH execution (for ECDH-1PU/authcrypt).
// The keyset handle will be set with either AES256-GCM, AES128CBC+SHA256, AES192CBC+SHA384, AES256CBC+SHA384 or
// AES256CBC+SHA512 AEAD key template for content encryption. With:
// - privKey the private key to convert.
// - aeadAlg the content encryption algorithm to use along the ECDH primitive.
func PrivateKeyToKeysetHandle(privKey *cryptoapi.PrivateKey, aeadAlg ecdh.AEADAlg) (*keyset.Handle, error) {
	// validate curve
	cp, err := getCurveProto(privKey.PublicKey.Curve)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to convert curve string to proto: %w", err)
	}

	kt, err := getKeyType(privKey.PublicKey.Type)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to convert key type to proto: %w", err)
	}

	encT, keyURL, err := keyTemplateAndURL(cp, aeadAlg, false)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: %w", err)
	}

	protoKey := &ecdhpb.EcdhAeadPrivateKey{
		Version: 0,
		PublicKey: &ecdhpb.EcdhAeadPublicKey{
			Version: 0,
			Params: &ecdhpb.EcdhAeadParams{
				KwParams: &ecdhpb.EcdhKwParams{
					CurveType: cp,
					KeyType:   kt,
				},
				EncParams: &ecdhpb.EcdhAeadEncParams{
					AeadEnc: encT,
				},
				EcPointFormat: commonpb.EcPointFormat_UNCOMPRESSED,
			},
			KID: privKey.PublicKey.KID,
			X:   privKey.PublicKey.X,
			Y:   privKey.PublicKey.Y,
		},
		KeyValue: privKey.D,
	}

	marshalledKey, err := proto.Marshal(protoKey)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to marshal proto: %w", err)
	}

	ks := newKeySet(keyURL, marshalledKey, tinkpb.KeyData_ASYMMETRIC_PRIVATE)

	memReader := &keyset.MemReaderWriter{Keyset: ks}

	parsedHandle, err := insecurecleartextkeyset.Read(memReader)
	if err != nil {
		return nil, fmt.Errorf("privateKeyToKeysetHandle: failed to create key handle: %w", err)
	}

	return parsedHandle, nil
}

var keyTemplateToPublicKeyURL = map[commonpb.EllipticCurveType]string{ //nolint:gochecknoglobals
	commonpb.EllipticCurveType_NIST_P256:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P384:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P521:  nistPECDHKWPublicKeyTypeURL,
	commonpb.EllipticCurveType_CURVE25519: x25519ECDHKWPublicKeyTypeURL,
}

var keyTemplateToPrivateKeyURL = map[commonpb.EllipticCurveType]string{ //nolint:gochecknoglobals
	commonpb.EllipticCurveType_NIST_P256:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P384:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_NIST_P521:  nistPECDHKWPrivateKeyTypeURL,
	commonpb.EllipticCurveType_CURVE25519: x25519ECDHKWPrivateKeyTypeURL,
}

func keyTemplateAndURL(cp commonpb.EllipticCurveType, aeadAlg ecdh.AEADAlg,
	isPublic bool) (*tinkpb.KeyTemplate, string, error) {
	// set ecdh kw public keyTypeURL.
	var (
		encT   *tinkpb.KeyTemplate
		keyURL string
	)

	if isPublic {
		keyURL = keyTemplateToPublicKeyURL[cp]
	} else {
		keyURL = keyTemplateToPrivateKeyURL[cp]
	}

	if keyURL == "" {
		return nil, "", fmt.Errorf("invalid key curve: '%v'", cp)
	}

	// set aeadAlg encryption primitive template.
	switch aeadAlg {
	case ecdh.AES256GCM:
		encT = tinkaead.AES256GCMKeyTemplate()
	case ecdh.XC20P:
		encT = tinkaead.XChaCha20Poly1305KeyTemplate()
	case ecdh.AES128CBCHMACSHA256:
		encT = aead.AES128CBCHMACSHA256KeyTemplate()
	case ecdh.AES192CBCHMACSHA384:
		encT = aead.AES192CBCHMACSHA384KeyTemplate()
	case ecdh.AES256CBCHMACSHA384:
		encT = aead.AES256CBCHMACSHA384KeyTemplate()
	case ecdh.AES256CBCHMACSHA512:
		encT = aead.AES256CBCHMACSHA512KeyTemplate()
	default:
		return nil, "", fmt.Errorf("invalid encryption algorithm: '%v'", ecdh.EncryptionAlgLabel[aeadAlg])
	}

	return encT, keyURL, nil
}

func getCurveProto(c string) (commonpb.EllipticCurveType, error) {
	switch c {
	case "secp256r1", "NIST_P256", "P-256", "EllipticCurveType_NIST_P256":
		return commonpb.EllipticCurveType_NIST_P256, nil
	case "secp384r1", "NIST_P384", "P-384", "EllipticCurveType_NIST_P384":
		return commonpb.EllipticCurveType_NIST_P384, nil
	case "secp521r1", "NIST_P521", "P-521", "EllipticCurveType_NIST_P521":
		return commonpb.EllipticCurveType_NIST_P521, nil
	case commonpb.EllipticCurveType_CURVE25519.String(), "X25519":
		return commonpb.EllipticCurveType_CURVE25519, nil
	default:
		return commonpb.EllipticCurveType_UNKNOWN_CURVE, errors.New("unsupported curve")
	}
}

func getKeyType(k string) (ecdhpb.KeyType, error) {
	switch k {
	case ecdhpb.KeyType_EC.String():
		return ecdhpb.KeyType_EC, nil
	case ecdhpb.KeyType_OKP.String():
		return ecdhpb.KeyType_OKP, nil
	default:
		return ecdhpb.KeyType_UNKNOWN_KEY_TYPE, errors.New("unsupported key type")
	}
}

func newKeySet(tURL string, marshalledKey []byte, keyMaterialType tinkpb.KeyData_KeyMaterialType) *tinkpb.Keyset {
	keyData := &tinkpb.KeyData{
		TypeUrl:         tURL,
		Value:           marshalledKey,
		KeyMaterialType: keyMaterialType,
	}

	return &tinkpb.Keyset{
		Key: []*tinkpb.Keyset_Key{
			{
				KeyData: keyData,
				Status:  tinkpb.KeyStatusType_ENABLED,
				KeyId:   1,
				// since we're building the key from raw key bytes, then must use raw key prefix type
				OutputPrefixType: tinkpb.OutputPrefixType_RAW,
			},
		},
		PrimaryKeyId: 1,
	}
}
