/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/spi/storage"
)

const (
	profileStoreName          = "vcwallet_profiles"
	profileStoreUserKeyPrefix = "vcwallet_usr_%s"
)

// ErrProfileNotFound error for wallet profile not found scenario.
var ErrProfileNotFound = errors.New("profile does not exist")

// profile of VC wallet contains wallet specific settings of wallet user to be remembered.
type profile struct {
	// ID unique identifier assigned to this wallet profile.
	ID string

	// User ID of the wallet profile user.
	User string

	// Encrypted MasterLock is for localkms.
	MasterLockCipher string

	// KeyServerURL for remotekms.
	KeyServerURL string

	// EDV configuration
	EDVConf *edvConf
}

type edvConf struct {
	// ServerURL for encrypted data vault storage of wallet contents.
	ServerURL string

	// VaultID for encrypted data vault storage of wallet contents.
	VaultID string

	// Key ID for encryption key for EDV.
	EncryptionKeyID string

	// Key ID for MAC key for EDV.
	MACKeyID string
}

// createProfile creates new verifiable credential wallet profile for given user and saves it in store.
// This profile is required for creating verifiable credential wallet client.
func createProfile(user string, opts *profileOpts) (*profile, error) {
	profile := &profile{User: user, ID: uuid.New().String()}

	err := profile.setKMSOptions(opts.passphrase, opts.secretLockSvc, opts.keyServerURL)
	if err != nil {
		return nil, err
	}

	err = profile.setEDVOptions(opts.edvConf)
	if err != nil {
		return nil, err
	}

	return profile, nil
}

func (pr *profile) setKMSOptions(passphrase string, secretLockSvc secretlock.Service, keyServerURL string) error {
	pr.resetKMSOptions()

	var err error

	switch {
	case passphrase != "":
		// localkms with passphrase
		secretLockSvc, err = getDefaultSecretLock(passphrase)
		if err != nil {
			return err
		}

		pr.MasterLockCipher, err = createMasterLock(secretLockSvc)
		if err != nil {
			return err
		}
	case secretLockSvc != nil:
		// localkms with secret lock service
		pr.MasterLockCipher, err = createMasterLock(secretLockSvc)
		if err != nil {
			return err
		}
	case keyServerURL != "":
		// remotekms
		pr.KeyServerURL = keyServerURL
	default:
		return fmt.Errorf("invalid create profile options")
	}

	return nil
}

func (pr *profile) setEDVOptions(opts *edvConf) error {
	if opts == nil {
		return nil
	}

	if opts.ServerURL == "" || opts.VaultID == "" {
		return errors.New("invalid EDV settings in profile")
	}

	pr.EDVConf = opts

	return nil
}

func (pr *profile) setupEDVEncryptionKey(keyManager kms.KeyManager) error {
	kid, _, err := keyManager.Create(kms.NISTP256ECDHKWType)
	if err != nil {
		return err
	}

	pr.EDVConf.EncryptionKeyID = kid

	return nil
}

func (pr *profile) setupEDVMacKey(keyManager kms.KeyManager) error {
	kid, _, err := keyManager.Create(kms.HMACSHA256Tag256Type)
	if err != nil {
		return err
	}

	pr.EDVConf.MACKeyID = kid

	return nil
}

func (pr *profile) resetKMSOptions() {
	pr.KeyServerURL = ""
	pr.MasterLockCipher = ""
}

// getUserKeyPrefix is key prefix for vc wallet profile store user key.
func getUserKeyPrefix(user string) string {
	return fmt.Sprintf(profileStoreUserKeyPrefix, user)
}

// newProfileStore creates new profile store.
func newProfileStore(provider storage.Provider) (*profileStore, error) {
	store, err := provider.OpenStore(profileStoreName)
	if err != nil {
		return nil, err
	}

	return &profileStore{store: store}, nil
}

// profileStore is store for vc wallet profiles contains unique collection of user profile info.
// key --> userID, val --> profile.
type profileStore struct {
	store storage.Store
}

// getProfile gets profile from store.
func (p *profileStore) get(user string) (*profile, error) {
	profileBytes, err := p.store.Get(getUserKeyPrefix(user))
	if err != nil {
		if errors.Is(err, storage.ErrDataNotFound) {
			return nil, ErrProfileNotFound
		}

		return nil, err
	}

	var result profile

	err = json.Unmarshal(profileBytes, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

// save saves profile into store,
// if argument 'override=true' then replaces existing profile else returns error.
func (p *profileStore) save(val *profile, override bool) error {
	if !override {
		profileBytes, _ := p.get(val.User) //nolint: errcheck
		if profileBytes != nil {
			return fmt.Errorf("profile already exists for given user")
		}
	}

	profileBytes, err := json.Marshal(val)
	if err != nil {
		return err
	}

	return p.store.Put(getUserKeyPrefix(val.User), profileBytes)
}
