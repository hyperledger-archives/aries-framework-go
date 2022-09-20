/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package testdata

import _ "embed" // required for tests only

// Sample testdata files to be used for tests only.
// nolint:gochecknoglobals
var (
	//go:embed samples/wallet/credential_manifest_multiple_vcs.json
	CredentialManifestMultipleVCs []byte
	//go:embed samples/wallet/VP_with_multiple_VCs_and_credential_response.json
	CredentialResponseWithMultipleVCs []byte
	//go:embed samples/wallet/sample_udc_vc.json
	SampleUDCVC []byte
	//go:embed samples/wallet/sample_udc_jwtvc.txt
	SampleUDCJWTVC []byte
	//go:embed samples/wallet/sample_udc_vc_signed.json
	SampleUDCVCWithProof []byte
	//go:embed samples/wallet/sample_udc_vc_with_credschema.json
	SampleUDCVCWithCredentialSchema []byte
	//go:embed samples/wallet/sample_udc_bbsvc_signed.json
	SampleUDCVCWithProofBBS []byte
	//go:embed samples/wallet/sample_invalid_did.json
	SampleInvalidDID []byte
	//go:embed samples/wallet/sample_docresolution_response.json
	SampleDocResolutionResponse []byte
	//go:embed samples/wallet/sample_bbs_frame.json
	SampleFrame []byte
	//go:embed samples/wallet/sample_content_metadata.json
	SampleWalletContentMetadata []byte
	//go:embed samples/wallet/sample_content_keybase58.json
	SampleWalletContentKeyBase58 []byte
	//go:embed samples/wallet/sample_query_by_frame.json
	SampleWalletQueryByFrame []byte
	//go:embed samples/wallet/sample_query_by_example.json
	SampleWalletQueryByExample []byte
	//go:embed samples/wallet/sample_presentation.json
	SampleUDCPresentation []byte
)
