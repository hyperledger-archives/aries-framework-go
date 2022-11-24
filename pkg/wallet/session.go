/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package wallet

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/bluele/gcache"
	"github.com/pkg/errors"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

// ErrInvalidAuthToken when auth token provided to wallet is unable to unlock key manager.
var ErrInvalidAuthToken = errors.New("invalid auth token")

const (
	// default cache expiry time.
	defaultCacheExpiry = 10 * time.Minute
	sessionTokenSize   = 32
)

// Session represent a session object created when user unlock wallet.
type Session struct {
	KeyManager    kms.KeyManager
	sessionExpiry time.Duration
	user          string
}

// sessionManagerInstance is key manager store singleton - access only via sessionManager()
//
//nolint:gochecknoglobals
var (
	sessionManagerInstance  *walletSessionManager
	sessionManagerStoreOnce sync.Once
)

func sessionManager() *walletSessionManager {
	sessionManagerStoreOnce.Do(func() {
		sessionManagerInstance = &walletSessionManager{
			gstore: gcache.New(0).Build(),
		}
	})

	return sessionManagerInstance
}

type walletSessionManager struct {
	gstore gcache.Cache
	mu     sync.Mutex
}

func (s *walletSessionManager) createSession(userID string, keyManager kms.KeyManager,
	sessionExpiry time.Duration) (string, error) {
	if sessionExpiry == 0 {
		sessionExpiry = defaultCacheExpiry
	}

	session := &Session{
		KeyManager:    keyManager,
		sessionExpiry: sessionExpiry,
		user:          userID,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, sess := range s.gstore.GetALL(true) {
		if sess.(*Session).user == userID {
			return "", ErrAlreadyUnlocked
		}
	}

	for {
		token, err := s.generateToken()
		if err != nil {
			return "", err
		}

		if !s.gstore.Has(token) {
			err = s.gstore.SetWithExpire(token, session, sessionExpiry)

			if err != nil {
				return "", fmt.Errorf("set with expire failed: %w", err)
			}

			return token, nil
		}
	}
}

func (s *walletSessionManager) getSession(authToken string) (*Session, error) {
	sess, err := s.gstore.Get(authToken)
	if err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			return nil, ErrInvalidAuthToken
		}

		return nil, fmt.Errorf("failed to get session object: %w", err)
	}

	session, ok := sess.(*Session)
	if !ok {
		return nil, fmt.Errorf("failed to cast session object: expects Session, gets %T", sess)
	}

	err = s.gstore.SetWithExpire(authToken, session, session.sessionExpiry)
	if err != nil {
		return nil, fmt.Errorf("set with expire failed: %w", err)
	}

	return session, nil
}

func wrapSessionError(err error) error {
	if errors.Is(err, ErrInvalidAuthToken) {
		return ErrWalletLocked
	}

	return fmt.Errorf("failed to get session: %w", err)
}

func (s *walletSessionManager) closeSession(userID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, sess := range s.gstore.GetALL(true) {
		if sess.(*Session).user == userID {
			return s.gstore.Remove(token)
		}
	}

	return false
}

func (s *walletSessionManager) generateToken() (string, error) {
	tokenBytes := make([]byte, sessionTokenSize)

	_, err := rand.Read(tokenBytes)
	if err != nil {
		return "", fmt.Errorf("failed to create random sessoin token: %w", err)
	}

	return hex.EncodeToString(tokenBytes), nil
}
