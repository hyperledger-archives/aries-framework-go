/*
Copyright Avast Software. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package common

type recursiveData struct {
	disclosures          map[string]*DisclosureClaim
	nestedSD             []string
	cleanupDigestsClaims bool
}
