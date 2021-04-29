/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

//nolint
package wallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bluele/gcache"

	"github.com/hyperledger/aries-framework-go/component/storage/edv"

	"github.com/hyperledger/aries-framework-go/pkg/crypto"
	"github.com/hyperledger/aries-framework-go/pkg/crypto/tinkcrypto"
	"github.com/hyperledger/aries-framework-go/pkg/didcomm/packer"
	"github.com/hyperledger/aries-framework-go/pkg/doc/jose"
	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

// storageProvider all wallet content storage provider operations.
// if profile has EDV settings then call to OpenStore will return EDV store instance by creating new EDV provider.
// Otherwise default provider will be used to open store.
// (Refer #2745 for more details)
type storageProvider struct {
	profile         *profile
	defaultProvider storage.Provider
}

func newWalletStorageProvider(profile *profile, provider storage.Provider) *storageProvider {
	return &storageProvider{profile: profile, defaultProvider: provider}
}

// OpenStore opens and returns store and sets store config to provider.
// if wallet profile has EDV settings then auth provided will be used to initialize edv storage provider.
func (s *storageProvider) OpenStore(auth string, opts *unlockOpts, config storage.StoreConfiguration) (storage.Store, error) {
	var provider storage.Provider
	var err error

	if s.profile.EDVConf != nil {
		provider, err = createEDVStorageProvider(auth, s.profile.EDVConf, opts)
		if err != nil {
			return nil, err
		}
	} else {
		provider = s.defaultProvider
	}

	store, err := provider.OpenStore(s.profile.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to open store : %w", err)
	}

	err = provider.SetStoreConfig(s.profile.ID, config)
	if err != nil {
		e := store.Close()
		if e != nil {
			logger.Warnf("failed to close store: %s", e)
		}

		return nil, fmt.Errorf("failed to set store config: %w", err)
	}

	return store, nil
}

func createEDVStorageProvider(auth string, conf *edvConf, opts *unlockOpts) (storage.Provider, error) {
	if conf.EncryptionKeyID == "" || conf.MACKeyID == "" {
		return nil, errors.New("invalid EDV configuration found in wallet profile, key IDs for encryption and MAC operations are missing") //nolint: lll
	}

	// get key manager
	keyMgr, err := keyManager().getKeyManger(auth)
	if err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			return nil, ErrWalletLocked
		}

		return nil, err
	}

	// get crypto
	cryptoImpl, err := tinkcrypto.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto: %w", err)
	}

	// get jwe encrypter
	jweEncrypter, err := getJWSEncrypter(conf.EncryptionKeyID, keyMgr, cryptoImpl)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWE encrypter: %w", err)
	}

	// get jwe decrypter
	jweDecrypter := jose.NewJWEDecrypt(nil, cryptoImpl, keyMgr)

	// get MAC crypto
	macCrypto, err := getMacCrypto(conf.MACKeyID, keyMgr, cryptoImpl)
	if err != nil {
		return nil, fmt.Errorf("failed to create mac crypto: %w", err)
	}

	var edvOpts []edv.RESTProviderOption
	if opts != nil {
		edvOpts = append(edvOpts, opts.edvOpts...)
	}

	// create EDV provider
	return edv.NewRESTProvider(conf.ServerURL, conf.VaultID,
		edv.NewEncryptedFormatter(jweEncrypter, jweDecrypter, macCrypto, edv.WithDeterministicDocumentIDs()),
		edvOpts...), nil
}

// getJWSEncrypter creates and returns jwe encrypter based on key manager & crypto provided
func getJWSEncrypter(kid string, keyMgr kms.KeyManager, cryptoImpl crypto.Crypto) (*jose.JWEEncrypt, error) {
	pubKeyBytes, err := keyMgr.ExportPubKeyBytes(kid)
	if err != nil {
		return nil, err
	}

	ecPubKey := new(crypto.PublicKey)

	ecPubKey.KID = kid

	err = json.Unmarshal(pubKeyBytes, ecPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal JWE public key bytes to an EC public key: %w", err)
	}

	return jose.NewJWEEncrypt(jose.A256GCM, packer.EnvelopeEncodingTypeV2, "", "", nil,
		[]*crypto.PublicKey{ecPubKey}, cryptoImpl)
}

// getMacCrypto creates and returns MAC crypto based on key manager & crypto provided
func getMacCrypto(kid string, keyMgr kms.KeyManager, cryptoImpl crypto.Crypto) (*edv.MACCrypto, error) {
	keyHandle, err := keyMgr.Get(kid)
	if err != nil {
		return nil, err
	}

	return edv.NewMACCrypto(keyHandle, cryptoImpl), nil
}
