/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package transport

// Envelope contain msg, FromVerKey and ToVerKeys
type Envelope struct {
	Message    []byte
	FromVerKey string
	ToVerKeys  []string
}
