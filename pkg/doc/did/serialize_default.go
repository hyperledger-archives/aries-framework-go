// +build !ACAPyInterop

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package did

const doACAPYInterop = false

// SerializeInterop serializes the DID doc, using normal serialization unless the `interop` build flag is set.
func (doc *Doc) SerializeInterop() ([]byte, error) {
	return doc.JSONBytes()
}
