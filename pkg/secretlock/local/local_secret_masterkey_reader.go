/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"io"

	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/local"
)

// MasterKeyFromPath creates a new instance of a local secret lock Reader to read a master key stored in `path`.
func MasterKeyFromPath(path string) (io.Reader, error) {
	return local.MasterKeyFromPath(path)
}

// MasterKeyFromEnv creates a new instance of a local secret lock Reader
// to read a master key found in a env variable with key: `envPrefix` + `keyURI`.
func MasterKeyFromEnv(envPrefix, keyURI string) (io.Reader, error) {
	return local.MasterKeyFromEnv(envPrefix, keyURI)
}
