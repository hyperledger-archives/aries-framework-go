/*
Licensed under the Apache License, Version 2.0 (the "License");

you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package subtle

import (
	"fmt"
	"io"

	tinksubtle "github.com/google/tink/go/subtle"
	"golang.org/x/crypto/hkdf"
)

const (
	// Minimum tag size in bytes. This provides minimum 80-bit security strength.
	// nolint:gochecknoglobals,gomnd
	minTagSizeInBytes = uint32(10)
)

// Maximum tag size in bytes for each hash type
// nolint:gochecknoglobals,gomnd
var maxTagSizeInBytes = map[string]uint32{
	"SHA1":   uint32(20),
	"SHA256": uint32(32),
	"SHA512": uint32(64),
}

// validateHKDFParams validates parameters of HKDF constructor.
func validateHKDFParams(hash string, tagSize uint32) error {
	// validate tag size
	maxTagSize, found := maxTagSizeInBytes[hash]
	if !found {
		return fmt.Errorf("invalid hash algorithm")
	}

	if tagSize > 255*maxTagSize {
		return fmt.Errorf("tag size too big")
	}

	if tagSize < minTagSizeInBytes {
		return fmt.Errorf("tag size too small")
	}

	return nil
}

// ComputeHKDF extracts a pseudorandom key.
func ComputeHKDF(hashAlg string, key, salt, info []byte, tagSize uint32) ([]byte, error) {
	err := validateHKDFParams(hashAlg, tagSize)
	if err != nil {
		return nil, fmt.Errorf("hkdf: %s", err)
	}

	hashFunc := tinksubtle.GetHashFunc(hashAlg)
	if hashFunc == nil {
		return nil, fmt.Errorf("hkdf: invalid hash algorithm")
	}

	if len(salt) == 0 {
		salt = make([]byte, hashFunc().Size())
	}

	result := make([]byte, tagSize)
	kdf := hkdf.New(hashFunc, key, salt, info)

	n, err := io.ReadFull(kdf, result)
	if n != len(result) || err != nil {
		return nil, fmt.Errorf("compute of hkdf failed")
	}

	return result, nil
}
