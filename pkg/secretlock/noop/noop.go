/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

// Package noop provides a noop secret lock service. This allows for quick testing of key storage using the KMS. Keys
// stored with noop are unprotected. Therefore, this implementation is be used for testing purposes only.
// Production code must always use pkg/secretlock/local implementation. In order to minimize the impact on existing
// clients, noop is the default implementation in the framework. Therefore, the use of a context.WithSecretLock() option
// with a secretlock/local implementation is highly recommended to secure key storage in the KMS.
package noop

import (
	"github.com/hyperledger/aries-framework-go/component/kmscrypto/secretlock/noop"
)

// NoLock is a secret lock service that does no key wrapping (keys are not encrypted).
type NoLock = noop.NoLock
