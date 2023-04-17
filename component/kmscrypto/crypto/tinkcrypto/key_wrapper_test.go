/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package tinkcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/google/tink/go/aead"
	"github.com/google/tink/go/keyset"
	commonpb "github.com/google/tink/go/proto/common_go_proto"
	tinkpb "github.com/google/tink/go/proto/tink_go_proto"
	"github.com/google/tink/go/subtle/random"
	"github.com/google/tink/go/testkeyset"
	"github.com/google/tink/go/testutil"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/hyperledger/aries-framework-go/spi/crypto"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/ecdh"
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/composite/keyio"
	ecdhpb "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/proto/ecdh_aead_go_proto"
)

type mockKeyWrapperSupport struct {
	getCurveVal     elliptic.Curve
	getCurveErr     error
	generateKeyVal  interface{}
	generateKeyErr  error
	createCipherVal cipher.Block
	createCipherErr error
	wrapVal         []byte
	wrapErr         error
	unwrapVal       []byte
	unwrapErr       error
	deriveSen1PuVal []byte
	deriveSen1PuErr error
	deriveRec1PuVal []byte
	deriveRec1PuErr error
}

func (w *mockKeyWrapperSupport) getCurve(curve string) (elliptic.Curve, error) {
	return w.getCurveVal, w.getCurveErr
}

func (w *mockKeyWrapperSupport) generateKey(curve elliptic.Curve) (interface{}, error) {
	return w.generateKeyVal, w.generateKeyErr
}

func (w *mockKeyWrapperSupport) createPrimitive(kek []byte) (interface{}, error) {
	return w.createCipherVal, w.createCipherErr
}

func (w *mockKeyWrapperSupport) wrap(block interface{}, cek []byte) ([]byte, error) {
	return w.wrapVal, w.wrapErr
}

func (w *mockKeyWrapperSupport) unwrap(block interface{}, wrappedKey []byte) ([]byte, error) {
	return w.unwrapVal, w.unwrapErr
}

func (w *mockKeyWrapperSupport) deriveSender1Pu(kwAlg string, apu, apv, tag []byte, epPriv, sePrivKey,
	recPubKey interface{}, keySize int) ([]byte, error) {
	return w.deriveSen1PuVal, w.deriveSen1PuErr
}

func (w *mockKeyWrapperSupport) deriveRecipient1Pu(kwAlg string, apu, apv, tag []byte, epPub, sePubKey,
	rPrivKey interface{}, keySize int) ([]byte, error) {
	return w.deriveRec1PuVal, w.deriveRec1PuErr
}

func TestWrapKey_Failure(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(defKeySize))
	apu := []byte("sender")
	apv := []byte("recipient")

	// test WrapKey with mocked getCurve error
	c := Crypto{ecKW: &mockKeyWrapperSupport{getCurveErr: errors.New("bad Curve")}}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-ES kek derivation: deriveESKEK: error "+
		"deriveESWithECKey: failed to generate ephemeral key: convertRecKeyAndGenOrGetEPKEC: failed to get curve of "+
		"recipient key: bad Curve")

	// test WrapKey with mocked generateKey error
	c = Crypto{ecKW: &mockKeyWrapperSupport{generateKeyErr: errors.New("genKey failed")}}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-ES kek derivation: deriveESKEK: error "+
		"deriveESWithECKey: failed to generate ephemeral key: convertRecKeyAndGenOrGetEPKEC: failed to generate EPK: "+
		"genKey failed")

	epk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// test WrapKey with mocked createPrimitive error
	c = Crypto{
		ecKW: &mockKeyWrapperSupport{
			createCipherErr: errors.New("createPrimitive failed"),
			generateKeyVal:  epk,
		},
	}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: failed to create new AES Cipher: createPrimitive "+
		"failed")

	badRecipientKey := &crypto.PublicKey{
		Type: ecdhpb.KeyType_UNKNOWN_KEY_TYPE.String(),
	}

	_, err = c.WrapKey(cek, apu, apv, badRecipientKey, crypto.WithSender(recipientKey))
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-1PU kek derivation: derive1PUKEK: invalid"+
		" recipient key type for ECDH-1PU")

	badRecipientKey.Type = ecdhpb.KeyType_OKP.String()

	_, err = c.WrapKey(cek, apu, apv, badRecipientKey, crypto.WithSender(recipientKey))
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: error ECDH-1PU kek derivation: derive1PUKEK: OKP key"+
		" derivation error derive1PUWithOKPKey: failed to retrieve sender key: ksToPrivateX25519Key: bad key handle "+
		"format")

	aesCipher, err := aes.NewCipher(random.GetRandomBytes(uint32(defKeySize)))
	require.NoError(t, err)

	// test WrapKey with mocked Wrap call error
	c = Crypto{
		ecKW: &mockKeyWrapperSupport{
			createCipherVal: aesCipher,
			generateKeyVal:  epk,
			wrapErr:         errors.New("wrap error"),
		},
	}

	_, err = c.WrapKey(cek, apu, apv, recipientKey)
	require.EqualError(t, err, "wrapKey: deriveKEKAndWrap: failed to AES wrap key: wrap error")
}

func TestUnwrapKey_Failure(t *testing.T) {
	recipientKeyHandle, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKey, err := keyio.ExtractPrimaryPublicKey(recipientKeyHandle)
	require.NoError(t, err)

	cek := random.GetRandomBytes(uint32(defKeySize))
	apu := []byte("sender")
	apv := []byte("recipient")

	validCrypter, err := New()
	require.NoError(t, err)

	wpKey, err := validCrypter.WrapKey(cek, apu, apv, recipientKey)
	require.NoError(t, err)

	// test UnwrapKey with mocked getCurve error
	c := Crypto{ecKW: &mockKeyWrapperSupport{getCurveErr: errors.New("bad Curve")}}

	_, err = c.UnwrapKey(wpKey, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: error ECDH-ES kek derivation: deriveESKEKForUnwrap:"+
		" error: deriveESWithECKeyForUnwrap: failed to GetCurve: bad Curve")

	// test UnwrapKey with mocked createPrimitive error
	c = Crypto{
		ecKW: &mockKeyWrapperSupport{
			createCipherErr: errors.New("createPrimitive failed"),
			getCurveVal:     elliptic.P256(),
		},
	}

	_, err = c.UnwrapKey(wpKey, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: failed to create new AES Cipher: createPrimitive failed")

	// test UnwrapKey with mocked unwrap error
	aesCipher, err := aes.NewCipher(random.GetRandomBytes(uint32(defKeySize)))
	require.NoError(t, err)

	c = Crypto{
		ecKW: &mockKeyWrapperSupport{
			createCipherVal: aesCipher,
			getCurveVal:     elliptic.P256(),
			unwrapErr:       errors.New("unwrap error"),
		},
	}

	_, err = c.UnwrapKey(wpKey, recipientKeyHandle)
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: failed to AES unwrap key: unwrap error")

	// create a valid wrapped key with sender to test unwrap
	okpRecipientKH, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	okpRecipientKey, err := keyio.ExtractPrimaryPublicKey(okpRecipientKH)
	require.NoError(t, err)

	okpSenderKH, err := keyset.NewHandle(ecdh.X25519ECDHKWKeyTemplate())
	require.NoError(t, err)

	wk, err := validCrypter.WrapKey(cek, apu, apv, okpRecipientKey, crypto.WithSender(okpSenderKH),
		crypto.WithXC20PKW())
	require.NoError(t, err)

	badWK := &crypto.RecipientWrappedKey{
		KID:          wk.KID,
		EncryptedCEK: wk.EncryptedCEK,
		EPK:          crypto.PublicKey{Type: ecdhpb.KeyType_UNKNOWN_KEY_TYPE.String()},
		Alg:          wk.Alg,
		APU:          wk.APU,
		APV:          wk.APV,
	}

	okpSenderKey, err := keyio.ExtractPrimaryPublicKey(okpSenderKH)
	require.NoError(t, err)

	_, err = validCrypter.UnwrapKey(badWK, okpRecipientKH, crypto.WithSender(okpSenderKey))
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap:"+
		" invalid EPK key type for ECDH-1PU")

	// unwrap valid wk with invalid sender key should fail
	_, err = validCrypter.UnwrapKey(wk, okpRecipientKH, crypto.WithSender([]byte("badSenderKey")))
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap:"+
		" OKP key derivation error derive1PUWithOKPKeyForUnwrap: failed to retrieve sender key: ksToPublicX25519Key: "+
		"unsupported keyset type [98 97 100 83 101 110 100 101 114 75 101 121]")

	okpSenderPublicKH, err := okpSenderKH.Public()
	require.NoError(t, err)

	// unwrap with valid Sender key as *cryptoapi.Public key should pass
	k, err := validCrypter.UnwrapKey(wk, okpRecipientKH, crypto.WithSender(okpSenderKey))
	require.NoError(t, err)
	require.EqualValues(t, cek, k)

	// unwrap with valid Sender key as *keyset.Handle should pass
	k, err = validCrypter.UnwrapKey(wk, okpRecipientKH, crypto.WithSender(okpSenderPublicKH))
	require.NoError(t, err)
	require.EqualValues(t, cek, k)

	// unwrap with invalid sender key as keyset.Handle should fail
	badPrivateKeyProto := generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_CURVE25519,
		ecdhpb.KeyType_EC, aead.AES128GCMKeyTemplate(), random.GetRandomBytes(32))

	badPrivMarshalledProto, err := proto.Marshal(badPrivateKeyProto)
	require.NoError(t, err)

	badPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistPECDHKWPrivateKeyTypeURL, badPrivMarshalledProto, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{badPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	badPrivHK, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	_, err = validCrypter.UnwrapKey(wk, okpRecipientKH, crypto.WithSender(badPrivHK))
	require.EqualError(t, err, "unwrapKey: deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap:"+
		" OKP key derivation error derive1PUWithOKPKeyForUnwrap: failed to retrieve sender key: ksToPublicX25519Key: "+
		"failed to extract public key from keyset handle: extractPrimaryPublicKey: failed to get public key content: "+
		"undefined EC curve: unsupported curve")
}

func Test_ksToPrivateECDSAKey_Failure(t *testing.T) {
	recipientKey, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	recipientKeyPub, err := recipientKey.Public()
	require.NoError(t, err)

	_, err = ksToPrivateECDSAKey(recipientKeyPub)
	require.EqualError(t, err, "ksToPrivateECDSAKey: failed to extract sender key: extractPrivKey: "+
		"can't extract unsupported private key 'type.hyperledger.org/hyperledger.aries.crypto.tink"+
		".NistPEcdhKwPublicKey'")
}

func Test_ksToPublicECDSAKey_Failure(t *testing.T) {
	_, err := ksToPublicECDSAKey(nil, nil)
	require.EqualError(t, err, "ksToPublicECDSAKey: unsupported keyset type <nil>")

	symKey, err := keyset.NewHandle(aead.AES128GCMKeyTemplate())
	require.NoError(t, err)

	_, err = ksToPublicECDSAKey(symKey, nil)
	require.EqualError(t, err, "ksToPublicECDSAKey: failed to extract public key from keyset handle: "+
		"extractPrimaryPublicKey: failed to get public key content: exporting unencrypted secret key material "+
		"is forbidden")

	recipientKey, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	kw := &mockKeyWrapperSupport{
		getCurveErr: errors.New("getCurve error"),
	}

	_, err = ksToPublicECDSAKey(recipientKey, kw)
	require.EqualError(t, err, "ksToPublicECDSAKey: failed to GetCurve: getCurve error")
}

func Test_deriveKEKAndUnwrap_Failure(t *testing.T) {
	c := Crypto{
		ecKW: &mockKeyWrapperSupport{},
	}

	recKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	_, err = c.deriveKEKAndUnwrap(ECDH1PUA256KWAlg, nil, nil, nil, nil, nil, nil, nil)
	require.EqualError(t, err, "deriveKEKAndUnwrap: bad key handle format")

	_, err = c.deriveKEKAndUnwrap(ECDH1PUA256KWAlg, nil, nil, nil, nil, nil, nil, recKH)
	require.EqualError(t, err, "deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap: sender's"+
		" public keyset handle option is required for 'ECDH-1PU+A256KW'")

	c.ecKW = &mockKeyWrapperSupport{
		getCurveErr: errors.New("getCurve error"),
	}

	senderKH, err := keyset.NewHandle(ecdh.NISTP256ECDHKWKeyTemplate())
	require.NoError(t, err)

	epk := &crypto.PublicKey{
		Type: ecdhpb.KeyType_EC.String(),
	}

	_, err = c.deriveKEKAndUnwrap(ECDH1PUA256KWAlg, nil, nil, nil, nil, epk, senderKH, recKH)
	require.EqualError(t, err, "deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap: EC key"+
		" derivation error derive1PUWithECKeyForUnwrap: failed to retrieve sender key: ksToPublicECDSAKey: failed to"+
		" GetCurve: getCurve error")

	c.ecKW = &mockKeyWrapperSupport{
		deriveRec1PuErr: errors.New("derive recipient 1pu error"),
	}

	epk.Curve = commonpb.EllipticCurveType_NIST_P256.String()
	_, err = c.deriveKEKAndUnwrap(ECDH1PUA256KWAlg, nil, nil, nil, nil, epk, senderKH, recKH)
	require.EqualError(t, err, "deriveKEKAndUnwrap: error ECDH-1PU kek derivation: derive1PUKEKForUnwrap: EC key"+
		" derivation error derive1PUWithECKeyForUnwrap: failed to derive kek: derive recipient 1pu error")
}

func Test_wrapRaw_Failure(t *testing.T) {
	c := Crypto{
		ecKW: &mockKeyWrapperSupport{},
		okpKW: &mockKeyWrapperSupport{
			createCipherErr: errors.New("bad primitive"),
		},
	}

	_, err := c.wrapRaw(nil, nil, nil, nil, "", "", nil, true)
	require.EqualError(t, err, "deriveKEKAndWrap: failed to create new XC20P primitive: bad primitive")

	c.okpKW = &mockKeyWrapperSupport{
		wrapErr: errors.New("wrap failed"),
	}

	_, err = c.wrapRaw(nil, nil, nil, nil, "", "", nil, true)
	require.EqualError(t, err, "deriveKEKAndWrap: failed to XC20P wrap key: wrap failed")
}

func Test_unwrapRaw_Failure(t *testing.T) {
	c := Crypto{}

	_, err := c.unwrapRaw("badAlg", nil, nil)
	require.EqualError(t, err, "deriveKEKAndUnwrap: cannot unwrap with bad kw alg: 'badAlg'")

	c.okpKW = &mockKeyWrapperSupport{
		createCipherErr: errors.New("bad primitive"),
	}

	_, err = c.unwrapRaw(ECDHESXC20PKWAlg, nil, nil)
	require.EqualError(t, err, "deriveKEKAndUnwrap: failed to create new XC20P primitive: bad primitive")

	c.okpKW = &mockKeyWrapperSupport{
		unwrapErr: errors.New("unwrap failed"),
	}

	_, err = c.unwrapRaw(ECDHESXC20PKWAlg, nil, nil)
	require.EqualError(t, err, "deriveKEKAndUnwrap: failed to XC20P unwrap key: unwrap failed")
}

func Test_deriveKEKUnwrapFailureDueToExtractPrivKeyError(t *testing.T) {
	badPrivateKeyProto := generateECDHAEADPrivateKey(t, commonpb.EllipticCurveType_CURVE25519, // <-- invalid EC curve
		ecdhpb.KeyType_EC, aead.AES128GCMKeyTemplate(), random.GetRandomBytes(32))

	badPrivMarshalledProto, err := proto.Marshal(badPrivateKeyProto)
	require.NoError(t, err)

	badPrivKey := testutil.NewKey(
		testutil.NewKeyData(nistPECDHKWPrivateKeyTypeURL, badPrivMarshalledProto, tinkpb.KeyData_ASYMMETRIC_PRIVATE),
		tinkpb.KeyStatusType_ENABLED, 15, tinkpb.OutputPrefixType_RAW)

	privKeys := []*tinkpb.Keyset_Key{badPrivKey}
	privKeyset := testutil.NewKeyset(privKeys[0].KeyId, privKeys)
	badPrivHK, err := testkeyset.NewHandle(privKeyset)
	require.NoError(t, err)

	c := Crypto{}
	_, err = c.deriveKEKAndUnwrap("", nil, nil, nil, nil, nil, nil, badPrivHK)
	require.EqualError(t, err, "deriveKEKAndUnwrap: extractPrivKey: invalid key: unsupported curve")
}

func Test_generateEphemeralOKPKey_Failure(t *testing.T) {
	c := Crypto{
		okpKW: &mockKeyWrapperSupport{
			generateKeyErr: errors.New("generate failure"),
		},
	}

	_, _, err := c.generateOrGetEphemeralOKPKey(nil)
	require.EqualError(t, err, "generate failure")

	c.okpKW = &mockKeyWrapperSupport{
		generateKeyVal: &ecdsa.PrivateKey{},
	}

	_, _, err = c.generateOrGetEphemeralOKPKey(nil)
	require.EqualError(t, err, "invalid ephemeral key type, not OKP, want []byte for OKP")
}

func TestX25519ECDHVector(t *testing.T) {
	// keys from test vector found on https://tools.ietf.org/html/rfc7748#section-6.1
	alicePrivKeyHex := "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	alicePrivKey, err := hex.DecodeString(alicePrivKeyHex)
	require.NoError(t, err)

	alicePubKey, err := curve25519.X25519(alicePrivKey, curve25519.Basepoint)
	require.NoError(t, err)

	alicePubKeyVectorHex := "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	alicePubKeyVector, err := hex.DecodeString(alicePubKeyVectorHex)
	require.NoError(t, err)

	require.EqualValues(t, alicePubKeyVector, alicePubKey)
	require.Equal(t, alicePubKeyVectorHex, fmt.Sprintf("%x", alicePubKey))

	bobPrivKeyHex := "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	bobPrivKey, err := hex.DecodeString(bobPrivKeyHex)
	require.NoError(t, err)

	bobPubKey, err := curve25519.X25519(bobPrivKey, curve25519.Basepoint)
	require.NoError(t, err)

	bobPubKeyVectorHex := "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	bobPubKeyVector, err := hex.DecodeString(bobPubKeyVectorHex)
	require.NoError(t, err)

	require.EqualValues(t, bobPubKeyVector, bobPubKey)
	require.Equal(t, bobPubKeyVectorHex, fmt.Sprintf("%x", bobPubKey))

	sharedSecretFromAlice, err := curve25519.X25519(alicePrivKey, bobPubKey)
	require.NoError(t, err)

	sharedSecretFromBob, err := curve25519.X25519(bobPrivKey, alicePubKey)
	require.NoError(t, err)

	require.EqualValues(t, sharedSecretFromAlice, sharedSecretFromBob)

	sharedSecretVectorHex := "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742" // nolint: gosec // test
	sharedSecretVector, err := hex.DecodeString(sharedSecretVectorHex)
	require.NoError(t, err)

	require.EqualValues(t, sharedSecretVector, sharedSecretFromAlice)
	require.EqualValues(t, sharedSecretVector, sharedSecretFromBob)
}
