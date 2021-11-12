/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package internal

import "fmt"

const (
	// CredentialNameKey is the data key prefix for credentials in the verifiable store.
	CredentialNameKey = "vcname_"
	// PresentationNameKey is the data key prefix for presentations in the verifiable store.
	PresentationNameKey = "vpname_"

	credentialNameDataKeyPattern   = CredentialNameKey + "%s"
	presentationNameDataKeyPattern = PresentationNameKey + "%s"
)

// CredentialNameDataKey formats credential name into data key.
func CredentialNameDataKey(name string) string {
	return fmt.Sprintf(credentialNameDataKeyPattern, name)
}

// PresentationNameDataKey formats presentation name into data key.
func PresentationNameDataKey(name string) string {
	return fmt.Sprintf(presentationNameDataKeyPattern, name)
}
