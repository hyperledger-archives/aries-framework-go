/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

type recursiveData struct {
	wrappedClaims map[string]*wrappedClaim
	foundSDs      []string
	modifyValues  bool
}
