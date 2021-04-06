/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package local

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// MasterKeyFromPath creates a new instance of a local secret lock Reader to read a master key stored in `path`.
func MasterKeyFromPath(path string) (io.Reader, error) {
	masterKeyFile, err := os.OpenFile(filepath.Clean(path), os.O_RDONLY, 0o600)
	if err != nil {
		return nil, err
	}

	defer func() {
		err = masterKeyFile.Close()
		if err != nil {
			logger.Warnf("failed to close file: %w", err)
		}
	}()

	mkData := make([]byte, masterKeyLen)

	n, err := io.ReadFull(masterKeyFile, mkData)
	if err != nil {
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, err
		}
	}

	mkData = mkData[0:n]

	return bytes.NewReader(mkData), nil
}

// MasterKeyFromEnv creates a new instance of a local secret lock Reader
// to read a master key found in a env variable with key: `envPrefix` + `keyURI`.
func MasterKeyFromEnv(envPrefix, keyURI string) (io.Reader, error) {
	mk := os.Getenv(envPrefix + strings.ReplaceAll(keyURI, "/", "_"))
	if mk == "" {
		return nil, fmt.Errorf("masterKey not set")
	}

	return bytes.NewReader([]byte(mk)), nil
}
