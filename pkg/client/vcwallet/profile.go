/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vcwallet

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/aries-framework-go/pkg/secretlock"
	"github.com/hyperledger/aries-framework-go/pkg/storage"
)

const (
	profileStoreName          = "vcwallet_profiles"
	profileStoreUserKeyPrefix = "vcwallet_usr_%s"
)

// ErrProfileNotFound error for wallet profile not found scenario.
var ErrProfileNotFound = errors.New("profile does not exist")

// profile of VC wallet contains wallet specific settings of wallet user to be remembered.
type profile struct {
	// User ID of the wallet profile user.
	User string

	// Encrypted MasterLock is for localkms.
	MasterLockCipher string

	// KeyServerURL for remotekms.
	KeyServerURL string
}

// createProfile creates new verifiable credential wallet profile for given user and saves it in store.
// This profile is required for creating verifiable credential wallet client.
func createProfile(user, passphrase string, secretLockSvc secretlock.Service, keyServerURL string) (*profile, error) {
	profile := &profile{User: user}

	var err error

	switch {
	case passphrase != "":
		// localkms with passphrase
		secretLockSvc, err = getDefaultSecretLock(passphrase)
		if err != nil {
			return nil, err
		}

		profile.MasterLockCipher, err = createMasterLock(secretLockSvc)
		if err != nil {
			return nil, err
		}
		// local
	case secretLockSvc != nil:
		// localkms with secret lock service
		profile.MasterLockCipher, err = createMasterLock(secretLockSvc)
		if err != nil {
			return nil, err
		}
	case keyServerURL != "":
		// remotekms
		profile.KeyServerURL = keyServerURL
	default:
		return nil, fmt.Errorf("invalid create profile options")
	}

	return profile, nil
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
// if argument 'override=true' then replaces existing profile for given user else returns error.
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
