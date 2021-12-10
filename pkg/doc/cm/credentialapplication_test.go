/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package cm_test

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/doc/cm"
)

const unknownFormatName = "SomeUnknownFormat"

//go:embed testdata/valid_credential_application.json
var validCredentialApplication []byte //nolint:gochecknoglobals

//go:embed testdata/valid_credential_application_with_format.json
var validCredentialApplicationWithFormat []byte //nolint:gochecknoglobals

func TestUnmarshalAndValidateAgainstCredentialManifest(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		credentialApplication, err := cm.UnmarshalAndValidateAgainstCredentialManifest(
			validCredentialApplication, &credentialManifest)
		require.NoError(t, err)
		require.Equal(t, "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d", credentialApplication.ID)
	})
	t.Run("Failure during validation", func(t *testing.T) {
		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

		_, err := cm.UnmarshalAndValidateAgainstCredentialManifest(
			validCredentialApplication, &credentialManifest)
		require.EqualError(t, err, "invalid format for the given Credential Manifest: the Credential "+
			"Manifest specifies a format but the Credential Application does not")
	})
}

func TestCredentialApplication_Unmarshal(t *testing.T) {
	t.Run("Success", func(t *testing.T) {
		makeCredentialApplicationFromBytes(t, validCredentialApplication)
	})
	t.Run("Missing ID", func(t *testing.T) {
		credentialApplicationBytes := makeCredentialApplicationWithMissingID(t)

		var credentialApplication cm.CredentialApplication

		err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
		require.EqualError(t, err, "invalid Credential Application: missing ID")
	})
	t.Run("Missing Manifest ID", func(t *testing.T) {
		credentialApplicationBytes := makeCredentialApplicationWithMissingManifestID(t)

		var credentialApplication cm.CredentialApplication

		err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
		require.EqualError(t, err, "invalid Credential Application: missing manifest ID")
	})
}

func TestCredentialApplication_ValidateAgainstCredentialManifest(t *testing.T) {
	t.Run("Credential Manifest has no format and no presentation definition", func(t *testing.T) {
		t.Run("Credential Application has no format and no presentation definition", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplication)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.NoError(t, err)
		})
	})
	t.Run("Credential Manifest has a format", func(t *testing.T) {
		t.Run("Credential Application has no format", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplication)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: the Credential "+
				"Manifest specifies a format but the Credential Application does not")
		})
		t.Run("Credential App requests a JWT format not allowed by the Credential Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT algorithms: [SomeUnknownFormat ES256K "+
				"ES384]. One or more of these are not in the Credential Manifest's supported JWT algorithms: [EdDSA "+
				"ES256K ES384]")
		})
		t.Run("Cred App requests a JWT VC format not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTVCAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT VC algorithms: [SomeUnknownFormat "+
				"ES384]. One or more of these are not in the Credential Manifest's supported JWT VC algorithms: "+
				"[ES256K ES384]")
		})
		t.Run("Cred App requests a JWT VP format not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownJWTVPAlg(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT VP algorithms: [SomeUnknownFormat "+
				"ES256K]. One or more of these are not in the Credential Manifest's supported JWT VP algorithms: "+
				"[EdDSA ES256K]")
		})
		t.Run("Cred App requests an LDP proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP proof types: [SomeUnknownFormat]. "+
				"One or more of these are not in the Credential Manifest's supported LDP proof types: "+
				"[RsaSignature2018]")
		})
		t.Run("Cred App requests an LDP VC proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPVCProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP VC proof types: [SomeUnknownFormat "+
				"EcdsaSecp256k1Signature2019 Ed25519Signature2018]. One or more of these are not in the "+
				"Credential Manifest's supported LDP VC proof types: [JsonWebSignature2020 Ed25519Signature2018 "+
				"EcdsaSecp256k1Signature2019 RsaSignature2018]")
		})
		t.Run("Cred App requests an LDP VC proof type not allowed by the Cred Manifest", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationWithUnknownLDPVPProofType(t)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP VP proof types: [SomeUnknownFormat]. "+
				"One or more of these are not in the Credential Manifest's supported LDP VP proof types: "+
				"[Ed25519Signature2018]")
		})
		t.Run("Cred App requests JWT formats but the Cred Manifest's JWT format is nil", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

			credentialManifest := createCredentialManifestWithNilJWTFormat(t)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following JWT algorithms: [EdDSA ES256K ES384]. "+
				"One or more of these are not in the Credential Manifest's supported JWT algorithms: []")
		})
		t.Run("Cred App requests JWT formats but the Cred Manifest's LDP format is nil", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

			credentialManifest := createCredentialManifestWithNilLDPFormat(t)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.EqualError(t, err, "invalid format for the given Credential Manifest: invalid format "+
				"request: the Credential Application lists the following LDP proof types: [RsaSignature2018]. One "+
				"or more of these are not in the Credential Manifest's supported LDP proof types: []")
		})
		t.Run("Credential Application has a valid format", func(t *testing.T) {
			credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

			credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifestWithFormat)

			err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
			require.NoError(t, err)
		})
	})
	t.Run("Credential App's manifest ID does not match the given Credential Manifest", func(t *testing.T) {
		credentialApplication := makeCredentialApplicationWithUnknownManifestID(t)

		credentialManifest := makeCredentialManifestFromBytes(t, validCredentialManifest)

		err := credentialApplication.ValidateAgainstCredentialManifest(&credentialManifest)
		require.EqualError(t, err, "the Manifest ID of the Credential Application (SomeUnknownManifestID) "+
			"does not match the given Credential Manifest's ID (university_degree)")
	})
}

func makeCredentialApplicationFromBytes(t *testing.T,
	credentialApplicationBytes []byte) cm.CredentialApplication {
	var credentialApplication cm.CredentialApplication

	err := json.Unmarshal(credentialApplicationBytes, &credentialApplication)
	require.NoError(t, err)

	return credentialApplication
}

func makeCredentialApplicationWithMissingID(t *testing.T) []byte {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplication)

	credentialApplication.ID = ""

	credentialApplicationBytes, err := json.Marshal(credentialApplication)
	require.NoError(t, err)

	return credentialApplicationBytes
}

func makeCredentialApplicationWithMissingManifestID(t *testing.T) []byte {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplication)

	credentialApplication.ManifestID = ""

	credentialApplicationBytes, err := json.Marshal(credentialApplication)
	require.NoError(t, err)

	return credentialApplicationBytes
}

func makeCredentialApplicationWithUnknownJWTAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.Jwt.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownJWTVCAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.JwtVC.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownJWTVPAlg(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.JwtVP.Alg[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.Ldp.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPVCProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.LdpVC.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownLDPVPProofType(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.Format.LdpVP.ProofType[0] = unknownFormatName

	return credentialApplication
}

func makeCredentialApplicationWithUnknownManifestID(t *testing.T) cm.CredentialApplication {
	credentialApplication := makeCredentialApplicationFromBytes(t, validCredentialApplicationWithFormat)

	credentialApplication.ManifestID = "SomeUnknownManifestID"

	return credentialApplication
}
