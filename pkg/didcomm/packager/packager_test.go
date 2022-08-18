/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package packager_test

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	cryptoapi "github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	. "github.com/hyperledger/aries-framework-go/pkg/didcomm/packager"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/authcrypt"
	legacy "github.com/hyperledger/aries-framework-go/pkg/didcomm/packer/legacy/authcrypt"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/transport"
	"github.com/hyperledger/aries-framework-go/pkg/doc/did"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/jwkkid"
	"github.com/hyperledger/aries-framework-go/pkg/doc/util/kmsdidkey"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/kms/localkms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/didcomm"
	mockdiddoc "github.com/hyperledger/aries-framework-go/pkg/mock/diddoc"
	mockstorage "github.com/hyperledger/aries-framework-go/pkg/mock/storage"
	mockvdr "github.com/hyperledger/aries-framework-go/pkg/mock/vdr"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock/noop"
	"github.com/hyperledger/aries-framework-go/pkg/vdr/fingerprint"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const localKeyURI = "local-lock://test/key-uri/"

func TestNewPackagerMissingPrimaryPacker(t *testing.T) {
	mockedProviders := &mockProvider{
		primaryPacker: nil,
		packers:       nil,
	}

	_, err := New(mockedProviders)
	require.EqualError(t, err, "need primary packer to initialize packager")
}

func TestBaseKMSInPackager_UnpackMessage(t *testing.T) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	t.Run("test failed to create packer encMessage due to missing vdr in provider", func(t *testing.T) {
		// create a custom KMS instance with this provider
		customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
			crypto:        cryptoSvc,
		}

		_, err = authcrypt.New(mockedProviders, jose.A128CBCHS256)
		require.EqualError(t, err, "authcrypt: failed to create packer because vdr registry is empty")
	})

	t.Run("test failed to unmarshal encMessage", func(t *testing.T) {
		// create a custom KMS instance with this provider
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		require.NoError(t, err)

		mockedProviders := &mockProvider{
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
			crypto:        cryptoSvc,
			vdr:           &mockvdr.MockVDRegistry{},
		}

		testPacker, err := authcrypt.New(mockedProviders, jose.A128CBCHS256)
		require.NoError(t, err)

		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)
		_, err = packager.UnpackMessage(nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unexpected end of JSON input")
	})

	t.Run("test bad encoding type", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			storage:       mockstorage.NewMockStoreProvider(),
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
			crypto:        cryptoSvc,
			vdr:           &mockvdr.MockVDRegistry{},
		}
		testPacker, err := authcrypt.New(mockedProviders, jose.A192CBCHS384)
		require.NoError(t, err)

		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		msg := []byte(`{"protected":"` + base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"badtype"}`)) + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "message Type not recognized")

		msg = []byte(`{"protected":"` + "## NOT B64 ##" + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "illegal base64 data")

		msg = []byte(`{"protected":"` + base64.RawURLEncoding.EncodeToString([]byte(`## NOT JSON ##`)) + `"}`)

		_, err = packager.UnpackMessage(msg)
		require.Error(t, err)
		require.Contains(t, err.Error(), "invalid character")
	})

	t.Run("test key not found", func(t *testing.T) {
		storeMap := make(map[string]mockstorage.DBEntry)
		customStore := &mockstorage.MockStore{
			Store: storeMap,
		}

		// create a customKMS with a custom storage provider using the above store to access the store map.
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewCustomMockStoreProvider(customStore), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		mockedProviders := &mockProvider{
			kms:           customKMS,
			crypto:        cryptoSvc,
			primaryPacker: nil,
			packers:       nil,
			vdr:           &mockvdr.MockVDRegistry{},
		}
		testPacker, err := authcrypt.New(mockedProviders, jose.A256CBCHS512)
		require.NoError(t, err)

		// use a real testPacker and a real KMS to validate pack/unpack
		mockedProviders.primaryPacker = testPacker
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// fromKey is stored in the KMS
		_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
		require.NoError(t, err)

		fromDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(fromKey, kms.NISTP256ECDHKWType)
		require.NoError(t, err)

		// toVerKey is stored in the KMS as well
		toKID, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.NISTP256ECDHKWType)
		require.NoError(t, err)

		toDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(toKey, kms.NISTP256ECDHKWType)
		require.NoError(t, err)

		// PackMessage should pass with both value from and to keys
		packMsg, err := packager.PackMessage(&transport.Envelope{
			MediaTypeProfile: transport.MediaTypeV1EncryptedEnvelope,
			Message:          []byte("msg1"),
			FromKey:          []byte(fromDIDKey),
			ToKeys:           []string{toDIDKey},
		})
		require.NoError(t, err)

		// mock KMS without ToKey then try UnpackMessage
		delete(storeMap, toKID) // keys in storeMap are prefixed

		// It should fail since Recipient keys are not found in the KMS
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "unpack: authcrypt Unpack: no matching recipient in envelope")
	})

	t.Run("test Pack/Unpack fails", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		decryptValue := func(envelope []byte) (*transport.Envelope, error) {
			return nil, fmt.Errorf("unpack error")
		}

		mockedProviders := &mockProvider{
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
			crypto:        cryptoSvc,
			vdr:           &mockvdr.MockVDRegistry{},
		}

		// use a mocked packager with a mocked KMS to validate pack/unpack
		e := func(cty string, payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			p, e := authcrypt.New(mockedProviders, jose.A128CBCHS256)
			require.NoError(t, e)
			return p.Pack(cty, payload, senderPubKey, recipientsKeys)
		}

		mockPacker := &didcomm.MockAuthCrypt{
			DecryptValue: decryptValue,
			EncryptValue: e, Type: transport.MediaTypeV2EncryptedEnvelope + "-authcrypt",
		}

		mockedProviders.primaryPacker = mockPacker

		packager, err := New(mockedProviders)
		require.NoError(t, err)

		// use ECDH1PU type as we are using a sender key (ie: packer's FromKey is not empty aka authcrypt)
		_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.NISTP384ECDHKWType)
		require.NoError(t, err)

		fromDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(fromKey, kms.NISTP384ECDHKWType)
		require.NoError(t, err)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.NISTP384ECDHKWType)
		require.NoError(t, err)

		toDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(toKey, kms.NISTP384ECDHKWType)
		require.NoError(t, err)

		// try pack with nil envelope - should fail
		packMsg, err := packager.PackMessage(nil)
		require.EqualError(t, err, "packMessage: envelope argument is nil")
		require.Empty(t, packMsg)

		// now try to pack with non empty envelope - should pass
		packMsg, err = packager.PackMessage(&transport.Envelope{
			MediaTypeProfile: transport.MediaTypeV1EncryptedEnvelope,
			Message:          []byte("msg1"),
			FromKey:          []byte(fromDIDKey),
			ToKeys:           []string{toDIDKey},
		})
		require.NoError(t, err)
		require.NotEmpty(t, packMsg)

		// now try unpack - should fail since we mocked the packager's Unpack value to return "decrypt error"
		// see 'decryptValue' above
		_, err = packager.UnpackMessage(packMsg)
		require.Error(t, err)
		require.EqualError(t, err, "unpack: unpack error")

		// now mock pack failure to test PackMessage with non empty envelope
		e = func(cty string, payload []byte, senderPubKey []byte, recipientsKeys [][]byte) (bytes []byte, e error) {
			return nil, fmt.Errorf("pack error")
		}
		mockPacker = &didcomm.MockAuthCrypt{EncryptValue: e}
		mockedProviders.primaryPacker = mockPacker
		packager, err = New(mockedProviders)
		require.NoError(t, err)
		packMsg, err = packager.PackMessage(&transport.Envelope{
			MediaTypeProfile: transport.MediaTypeV1EncryptedEnvelope,
			Message:          []byte("msg1"),
			FromKey:          []byte(fromDIDKey),
			ToKeys:           []string{toDIDKey},
		})
		require.Error(t, err)
		require.Empty(t, packMsg)
		require.EqualError(t, err, "packMessage: failed to pack: pack error")
	})

	t.Run("test Pack/Unpack success", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		tests := []struct {
			name    string
			keyType kms.KeyType
		}{
			{
				name:    "Pack/Unpack success with P-256 ECDH KW keys",
				keyType: kms.NISTP256ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with P-384 ECDH KW keys",
				keyType: kms.NISTP384ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with P-521 ECDH KW keys",
				keyType: kms.NISTP521ECDHKWType,
			},
			{
				name:    "Pack/Unpack success with X25519 ECDH KW keys",
				keyType: kms.X25519ECDHKWType,
			},
		}

		for _, tt := range tests {
			tc := tt
			t.Run(tc.name, func(t *testing.T) {
				packUnPackSuccess(tc.keyType, customKMS, cryptoSvc, t)
			})
		}
	})

	t.Run("test success - dids not found", func(t *testing.T) {
		customKMS, err := localkms.New(localKeyURI,
			newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
		require.NoError(t, err)
		require.NotEmpty(t, customKMS)

		require.NoError(t, err)
		mockedProviders := &mockProvider{
			kms:           customKMS,
			primaryPacker: nil,
			packers:       nil,
		}

		// create a real testPacker (no mocking here)
		testPacker := legacy.New(mockedProviders)
		require.NoError(t, err)
		mockedProviders.primaryPacker = testPacker

		mockedProviders.packers = []packer.Packer{testPacker}

		// now create a new packager with the above provider context
		packager, err := New(mockedProviders)
		require.NoError(t, err)

		_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		fromDIDKey, _ := fingerprint.CreateDIDKey(fromKey)

		_, toKey, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)

		toDIDKey, _ := fingerprint.CreateDIDKey(toKey)

		// pack an non empty envelope - should pass
		packMsg, err := packager.PackMessage(&transport.Envelope{
			// not passing CTY intentionally because packager.primaryPacker is legacyPacker (it ignores CTY).
			Message: []byte("msg1"),
			FromKey: []byte(fromDIDKey),
			ToKeys:  []string{toDIDKey},
		})
		require.NoError(t, err)

		// unpack the packed message above - should pass and match the same payload (msg1)
		unpackedMsg, err := packager.UnpackMessage(packMsg)
		require.NoError(t, err)
		require.Equal(t, unpackedMsg.Message, []byte("msg1"))
	})
}

func packUnPackSuccess(keyType kms.KeyType, customKMS kms.KeyManager, cryptoSvc cryptoapi.Crypto, t *testing.T) {
	resolveDIDFunc, fromDIDKey, toDIDKey, fromDID, toDID := newDIDsAndDIDDocResolverFunc(customKMS,
		keyType, t)

	mockedProviders := &mockProvider{
		kms:           customKMS,
		primaryPacker: nil,
		packers:       nil,
		crypto:        cryptoSvc,
		// vdr context for DID doc resolution:
		vdr: &mockvdr.MockVDRegistry{
			ResolveFunc: resolveDIDFunc,
		},
	}

	// create a real testPacker (no mocking here)
	testPacker, err := authcrypt.New(mockedProviders, jose.A256CBCHS512)
	require.NoError(t, err)

	mockedProviders.primaryPacker = testPacker

	legacyPacker := legacy.New(mockedProviders)
	mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

	// now create a new packager with the above provider context
	packager, err := New(mockedProviders)
	require.NoError(t, err)

	// legacy packer uses ED25519 keys only
	_, fromKeyED25519, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519)
	require.NoError(t, err)

	fromDIDKeyED25519, _ := fingerprint.CreateDIDKey(fromKeyED25519)

	_, toKeyEd25519, err := customKMS.CreateAndExportPubKeyBytes(kms.ED25519)
	require.NoError(t, err)

	toLegacyDIDKey, _ := fingerprint.CreateDIDKey(toKeyEd25519)

	tests := []struct {
		name              string
		mediaType         string
		isKeyAgreementKey bool
	}{
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeRFC0019EncryptedEnvelope),
			mediaType: transport.MediaTypeRFC0019EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV1PlaintextPayload),
			mediaType: transport.MediaTypeV1PlaintextPayload,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV1EncryptedEnvelope),
			mediaType: transport.MediaTypeV1EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload),
			mediaType: transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV2PlaintextPayload),
			mediaType: transport.MediaTypeV2PlaintextPayload,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeV2EncryptedEnvelope),
			mediaType: transport.MediaTypeV2EncryptedEnvelope,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeAIP2RFC0019Profile),
			mediaType: transport.MediaTypeAIP2RFC0019Profile,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeProfileDIDCommAIP1),
			mediaType: transport.MediaTypeProfileDIDCommAIP1,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeAIP2RFC0587Profile),
			mediaType: transport.MediaTypeAIP2RFC0587Profile,
		},
		{
			name:      fmt.Sprintf("success using mediaType %s", transport.MediaTypeDIDCommV2Profile),
			mediaType: transport.MediaTypeDIDCommV2Profile,
		},
		{
			name: fmt.Sprintf("success using mediaType %s with KeyAgreement",
				transport.MediaTypeAIP2RFC0587Profile),
			mediaType:         transport.MediaTypeAIP2RFC0587Profile,
			isKeyAgreementKey: true,
		},
		{
			name:              fmt.Sprintf("success using mediaType %s with KeyAgreement", transport.MediaTypeDIDCommV2Profile),
			mediaType:         transport.MediaTypeDIDCommV2Profile,
			isKeyAgreementKey: true,
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			var (
				fromKIDPack []byte
				toKIDsPack  []string
			)

			switch tc.mediaType {
			case transport.MediaTypeRFC0019EncryptedEnvelope, transport.MediaTypeAIP2RFC0019Profile,
				transport.MediaTypeProfileDIDCommAIP1:
				fromKIDPack = []byte(fromDIDKeyED25519)
				toKIDsPack = []string{toLegacyDIDKey}
			case transport.MediaTypeV1EncryptedEnvelope, transport.MediaTypeV1PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeAIP2RFC0587Profile,
				transport.MediaTypeDIDCommV2Profile:
				if tc.isKeyAgreementKey {
					fromKIDPack = []byte(fromDID.KeyAgreement[0].VerificationMethod.ID)
					toKIDsPack = []string{toDID.KeyAgreement[0].VerificationMethod.ID}
				} else {
					fromKIDPack = []byte(fromDIDKey)
					toKIDsPack = []string{toDIDKey}
				}
			}

			// pack an non empty envelope using packer selected by mediaType - should pass
			packMsg, err := packager.PackMessage(&transport.Envelope{
				MediaTypeProfile: tc.mediaType,
				Message:          []byte("msg"),
				FromKey:          fromKIDPack,
				ToKeys:           toKIDsPack,
			})
			require.NoError(t, err)

			// unpack the packed message above - should pass and match the same payload (msg1)
			unpackedMsg, err := packager.UnpackMessage(packMsg)
			require.NoError(t, err)
			require.Equal(t, unpackedMsg.Message, []byte("msg"))

			switch tc.mediaType {
			case transport.MediaTypeV1EncryptedEnvelope, transport.MediaTypeV1PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelopeV1PlaintextPayload, transport.MediaTypeV2PlaintextPayload,
				transport.MediaTypeV2EncryptedEnvelope, transport.MediaTypeAIP2RFC0587Profile,
				transport.MediaTypeDIDCommV2Profile:
				// try to unpack with packedMsg base64 encoded and wrapped with double quotes.
				wrappedMsg := append([]byte("\""), []byte(base64.RawURLEncoding.EncodeToString(packMsg))...)
				wrappedMsg = append(wrappedMsg, []byte("\"")...)
				unpackedMsg, err = packager.UnpackMessage(wrappedMsg)
				require.NoError(t, err)
				require.Equal(t, unpackedMsg.Message, []byte("msg"))
			}
		})
	}
}

func TestPackagerLegacyInterop(t *testing.T) {
	customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
	require.NoError(t, err)
	require.NotEmpty(t, customKMS)

	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	resolveLegacyDIDFunc, legacyFromDID, legacyToDID := newLegacyDIDsAndDIDDocResolverFunc(t, customKMS)

	mockedProviders := &mockProvider{
		kms:           customKMS,
		primaryPacker: nil,
		packers:       nil,
		crypto:        cryptoSvc,
		// vdr context for DID doc resolution:
		vdr: &mockvdr.MockVDRegistry{
			ResolveFunc: resolveLegacyDIDFunc,
		},
	}

	legacyPacker := legacy.New(mockedProviders)
	mockedProviders.primaryPacker = legacyPacker
	mockedProviders.packers = []packer.Packer{legacyPacker}

	// now create a new packager with the above provider context
	packager, err := New(mockedProviders)
	require.NoError(t, err)

	tests := []struct {
		name              string
		mediaType         string
		isKeyAgreementKey bool
		fromKIDPack       []byte
		toKIDsPack        []string
	}{
		{
			name: fmt.Sprintf("success using mediaType %s with did key references",
				transport.MediaTypeRFC0019EncryptedEnvelope),
			mediaType:   transport.MediaTypeRFC0019EncryptedEnvelope,
			fromKIDPack: []byte(legacyFromDID.VerificationMethod[0].ID),
			toKIDsPack:  []string{legacyToDID.VerificationMethod[0].ID},
		},
		{
			name: fmt.Sprintf("success using mediaType %s with raw keys",
				transport.MediaTypeRFC0019EncryptedEnvelope),
			mediaType:   transport.MediaTypeRFC0019EncryptedEnvelope,
			fromKIDPack: legacyFromDID.VerificationMethod[0].Value,
			toKIDsPack:  []string{string(legacyToDID.VerificationMethod[0].Value)},
		},
	}

	for _, tt := range tests {
		tc := tt

		t.Run(tc.name, func(t *testing.T) {
			// pack a non-empty envelope using packer selected by mediaType - should pass
			packMsg, err := packager.PackMessage(&transport.Envelope{
				MediaTypeProfile: tc.mediaType,
				Message:          []byte("msg"),
				FromKey:          tc.fromKIDPack,
				ToKeys:           tc.toKIDsPack,
			})
			require.NoError(t, err)

			// unpack the packed message above - should pass and match the same payload (msg1)
			unpackedMsg, err := packager.UnpackMessage(packMsg)
			require.NoError(t, err)
			require.Equal(t, unpackedMsg.Message, []byte("msg"))
		})
	}
}

func TestPackager_PackMessage_DIDKey_Failures(t *testing.T) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
	require.NoError(t, err)

	mockedProviders := &mockProvider{
		kms:           customKMS,
		primaryPacker: nil,
		packers:       nil,
		crypto:        cryptoSvc,
		// vdr context for DID doc resolution:
		vdr: &mockvdr.MockVDRegistry{},
	}

	// create a real testPacker (no mocking here)
	testPacker, err := authcrypt.New(mockedProviders, jose.A256CBCHS512)
	require.NoError(t, err)

	mockedProviders.primaryPacker = testPacker

	legacyPacker := legacy.New(mockedProviders)
	mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

	// now create a new packager with the above provider context
	packager, err := New(mockedProviders)
	require.NoError(t, err)

	tests := []struct {
		name    string
		fromKey []byte
		toKeys  []string
		errMsg  string
	}{
		{
			name:   "pack error with invalid recipient key as didKey",
			toKeys: []string{"did:key:zInvalidKey"},
			errMsg: "packMessage: prepareSenderAndRecipientKeys: failed to parse public key bytes " +
				"from did:key verKey for recipient 1: encryptionPubKeyFromDIDKey: extractRawKey: " +
				"PubKeyFromFingerprint failure: unknown key encoding",
		},
		{
			name:    "pack error with invalid sender key as didKey",
			fromKey: []byte("did:key:zInvalidKey"),
			toKeys:  []string{"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F"},
			errMsg: "packMessage: prepareSenderAndRecipientKeys: failed to extract pubKeyBytes from senderVerKey: " +
				"encryptionPubKeyFromDIDKey: extractRawKey: PubKeyFromFingerprint " +
				"failure: unknown key encoding",
		},
		{
			name:    "pack error with invalid sender key not didKey nor keyAgreement",
			fromKey: []byte("zInvalidKey"),
			toKeys:  []string{"did:key:z6LSeu9HkTHSfLLeUs2nnzUSNedgDUevfNQgQjQC23ZCit6F"},
			errMsg: "packMessage: failed to pack: authcrypt Pack: failed to get sender key from KMS: getKeySet: " +
				"failed to read json keyset from reader: cannot read data for keysetID zInvalidKey: key not found. " +
				"Underlying error: data not found",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			_, err = packager.PackMessage(&transport.Envelope{
				Message: []byte("msg1"),
				FromKey: tc.fromKey,
				ToKeys:  tc.toKeys,
			})
			require.EqualError(t, err, tc.errMsg)
		})
	}
}

func TestPackager_PackMessage_KeyAgreementID_Failures(t *testing.T) {
	cryptoSvc, err := tinkcrypto.New()
	require.NoError(t, err)

	customKMS, err := localkms.New(localKeyURI, newMockKMSProvider(mockstorage.NewMockStoreProvider(), t))
	require.NoError(t, err)

	//nolint:dogsled
	resolveDIDFunc, _, _, _, toDID := newDIDsAndDIDDocResolverFunc(customKMS, kms.X25519ECDHKWType, t)

	mockedProviders := &mockProvider{
		kms:           customKMS,
		primaryPacker: nil,
		packers:       nil,
		crypto:        cryptoSvc,
		// vdr context for DID doc resolution:
		vdr: &mockvdr.MockVDRegistry{
			ResolveFunc: resolveDIDFunc,
		},
	}

	// create a real testPacker (no mocking here)
	testPacker, err := authcrypt.New(mockedProviders, jose.XC20P)
	require.NoError(t, err)

	mockedProviders.primaryPacker = testPacker

	legacyPacker := legacy.New(mockedProviders)
	mockedProviders.packers = []packer.Packer{testPacker, legacyPacker}

	// now create a new packager with the above provider context
	packager, err := New(mockedProviders)
	require.NoError(t, err)

	tests := []struct {
		name    string
		fromKey []byte
		toKeys  []string
		errMsg  string
	}{
		{
			name:   "pack error with invalid recipient key as keyAgreementID",
			toKeys: []string{toDID.ID + "#invalidKey"},
			errMsg: "packMessage: prepareSenderAndRecipientKeys: for recipient 1: resolveKeyAgreementFromDIDDoc: " +
				"keyAgreement ID 'did:peer:bobdid#invalidKey' not found in DID 'did:peer:bobdid'",
		},
		{
			name:    "pack error with invalid sender key as keyAgreementID",
			fromKey: []byte(toDID.ID + "#invalidKey"),
			toKeys:  []string{toDID.ID + "#key-4"},
			errMsg: "packMessage: prepareSenderAndRecipientKeys: for sender: resolveKeyAgreementFromDIDDoc: " +
				"keyAgreement ID 'did:peer:bobdid#invalidKey' not found in DID 'did:peer:bobdid'",
		},
		{
			name:    "pack error with invalid sender key as keyAgreementID from a bad DID",
			fromKey: []byte("did:peer:badDID#invalidKey"),
			toKeys:  []string{toDID.ID + "#key-4"},
			errMsg: "packMessage: prepareSenderAndRecipientKeys: for sender: resolveKeyAgreementFromDIDDoc: " +
				"for recipient DID doc resolution did not found: did:peer:badDID",
		},
	}

	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			_, err = packager.PackMessage(&transport.Envelope{
				Message: []byte("msg1"),
				FromKey: tc.fromKey,
				ToKeys:  tc.toKeys,
			})
			require.EqualError(t, err, tc.errMsg)
		})
	}
}

type resolverFunc func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error)

//nolint:lll
func newDIDsAndDIDDocResolverFunc(customKMS kms.KeyManager, keyType kms.KeyType, t *testing.T) (resolverFunc, string, string, *did.Doc, *did.Doc) {
	t.Helper()

	_, fromKey, err := customKMS.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	fromDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(fromKey, keyType)
	require.NoError(t, err)

	fromJWK, err := jwkkid.BuildJWK(fromKey, keyType)
	require.NoError(t, err)

	vmKeyType := "JsonWebKey2020"

	if keyType == kms.X25519ECDHKWType {
		vmKeyType = "X25519KeyAgreementKey2019"
	}

	fromDID := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "alicedid")
	fromKA, err := did.NewVerificationMethodFromJWK(
		fromDID.KeyAgreement[0].VerificationMethod.ID, vmKeyType, fromDID.ID, fromJWK)
	require.NoError(t, err)

	fromDID.KeyAgreement = []did.Verification{
		{
			VerificationMethod: *fromKA,
		},
	}

	_, toKey, err := customKMS.CreateAndExportPubKeyBytes(keyType)
	require.NoError(t, err)

	toDIDKey, err := kmsdidkey.BuildDIDKeyByKeyType(toKey, keyType)
	require.NoError(t, err)

	toJWK, err := jwkkid.BuildJWK(toKey, keyType)
	require.NoError(t, err)

	toDID := mockdiddoc.GetMockDIDDocWithDIDCommV2Bloc(t, "bobdid")
	toKA, err := did.NewVerificationMethodFromJWK(
		toDID.KeyAgreement[0].VerificationMethod.ID, vmKeyType, toDID.ID, toJWK)
	require.NoError(t, err)

	toDID.KeyAgreement = []did.Verification{
		{
			VerificationMethod: *toKA,
		},
	}

	resolveDID := func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
		switch didID {
		case toDID.ID:
			return &did.DocResolution{
				DIDDocument: toDID,
			}, nil
		case fromDID.ID:
			return &did.DocResolution{
				DIDDocument: fromDID,
			}, nil
		default:
			return nil, fmt.Errorf("did not found: %s", didID)
		}
	}

	return resolveDID, fromDIDKey, toDIDKey, fromDID, toDID
}

func makeRawKey(t *testing.T, customKMS kms.KeyManager) []byte {
	t.Helper()

	var (
		key []byte
		err error
	)

	// for tests using raw keys, we need raw keys that won't be misinterpreted as did key references.
	for key == nil || strings.Index(string(key), "#") > 0 { //nolint:gocritic // need to check with strings
		_, key, err = customKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.NoError(t, err)
	}

	return key
}

func newLegacyDIDsAndDIDDocResolverFunc(t *testing.T, customKMS kms.KeyManager) (resolverFunc, *did.Doc, *did.Doc) {
	t.Helper()

	fromKey := makeRawKey(t, customKMS)
	toKey := makeRawKey(t, customKMS)

	fromDID := mockdiddoc.GetLegacyInteropMockDIDDoc(t, "AliceDIDInterop", fromKey)
	toDID := mockdiddoc.GetLegacyInteropMockDIDDoc(t, "BobDIDInterop", toKey)

	resolveDID := func(didID string, opts ...vdrapi.DIDMethodOption) (*did.DocResolution, error) {
		switch didID {
		case toDID.ID:
			return &did.DocResolution{
				DIDDocument: toDID,
			}, nil
		case fromDID.ID:
			return &did.DocResolution{
				DIDDocument: fromDID,
			}, nil
		default:
			return nil, fmt.Errorf("did not found: %s", didID)
		}
	}

	return resolveDID, fromDID, toDID
}

type kmsProvider struct {
	kmsStore          kms.Store
	secretLockService secretlock.Service
}

func (k *kmsProvider) StorageProvider() kms.Store {
	return k.kmsStore
}

func (k *kmsProvider) SecretLock() secretlock.Service {
	return k.secretLockService
}

func newMockKMSProvider(storagePvdr *mockstorage.MockStoreProvider, t *testing.T) kms.Provider {
	ariesProviderWrapper, err := kms.NewAriesProviderWrapper(storagePvdr)
	require.NoError(t, err)

	return &kmsProvider{kmsStore: ariesProviderWrapper, secretLockService: &noop.NoLock{}}
}

// mockProvider mocks provider for KMS.
type mockProvider struct {
	storage       *mockstorage.MockStoreProvider
	kms           kms.KeyManager
	secretLock    secretlock.Service
	crypto        cryptoapi.Crypto
	packers       []packer.Packer
	primaryPacker packer.Packer
	vdr           vdrapi.Registry
}

func (m *mockProvider) Packers() []packer.Packer {
	return m.packers
}

func (m *mockProvider) KMS() kms.KeyManager {
	return m.kms
}

func (m *mockProvider) SecretLock() secretlock.Service {
	return m.secretLock
}

func (m *mockProvider) StorageProvider() storage.Provider {
	return m.storage
}

func (m *mockProvider) PrimaryPacker() packer.Packer {
	return m.primaryPacker
}

// VDRegistry returns a vdr registry.
func (m *mockProvider) VDRegistry() vdrapi.Registry {
	return m.vdr
}

func (m *mockProvider) Crypto() cryptoapi.Crypto {
	return m.crypto
}
