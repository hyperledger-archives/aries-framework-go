//go:build ursa
// +build ursa

/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"github.com/google/tink/go/keyset"
	"github.com/hyperledger/ursa-wrapper-go/pkg/libursa/ursa"
	"github.com/stretchr/testify/require"

	bld "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/blinder"
	sgn "github.com/hyperledger/aries-framework-go/component/kmscrypto/crypto/tinkcrypto/primitive/cl/signer"
	webkmsimpl "github.com/hyperledger/aries-framework-go/component/kmscrypto/kms/webkms"
)

func TestClMethods(t *testing.T) {
	sgnKh, err := keyset.NewHandle(sgn.CredDefKeyTemplate([]string{"attr1", "attr2"}))
	require.NoError(t, err)

	bldKh, err := keyset.NewHandle(bld.MasterSecretKeyTemplate())
	require.NoError(t, err)

	pubKh, err := sgnKh.Public()
	require.NoError(t, err)

	pubKey, err := sgn.ExportCredDefPubKey(pubKh)
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processClRequest(w, r, sgnKh, bldKh)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(webkmsimpl.KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)
	sgnKeyURL := defaultKeystoreURL + "/keys/SGN"
	bldKeyURL := defaultKeystoreURL + "/keys/BLD"
	rCrypto := New(defaultKeystoreURL, client)

	// test successful CL methods usage
	blinded, err := rCrypto.Blind(bldKeyURL, map[string]interface{}{"attr1": 1, "attr2": "aaa"})
	require.NoError(t, err)
	require.NotEmpty(t, blinded)

	// blind should work with no parameters
	_, err = rCrypto.Blind(bldKeyURL)
	require.NoError(t, err)

	correctnessProof, err := rCrypto.GetCorrectnessProof(sgnKeyURL)
	require.NoError(t, err)
	require.NotEmpty(t, correctnessProof)

	secrets, secretsProof, offerNonce, requestNonce := generateBlindedSecretsWithNonces(t,
		pubKey,
		correctnessProof,
		blinded[0],
	)

	sig, sigProof, err := rCrypto.SignWithSecrets(sgnKeyURL,
		map[string]interface{}{"attr1": 1, "attr2": "aaa"},
		secrets,
		secretsProof,
		[][]byte{offerNonce, requestNonce},
		"did:example:id",
	)
	require.NoError(t, err)
	require.NotEmpty(t, sig)
	require.NotEmpty(t, sigProof)

	t.Run("CL request failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpCrypto := New(defaultKeystoreURL, blankClient)

		var err error

		_, err = tmpCrypto.Blind(bldKeyURL)
		require.Error(t, err)

		_, err = tmpCrypto.GetCorrectnessProof(sgnKeyURL)
		require.Error(t, err)

		_, _, err = tmpCrypto.SignWithSecrets(sgnKeyURL,
			map[string]interface{}{},
			nil,
			nil,
			nil,
			"",
		)
		require.Error(t, err)
	})

	t.Run("CL json marshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.marshalFunc = failingMarshal

		var err error
		_, err = remoteCrypto2.Blind(bldKeyURL, map[string]interface{}{"attr1": 1, "attr2": "aaa"})
		require.Error(t, err)

		_, _, err = remoteCrypto2.SignWithSecrets(sgnKeyURL,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
			secrets,
			secretsProof,
			[][]byte{offerNonce, requestNonce},
			"did:example:id",
		)
		require.Error(t, err)
	})

	t.Run("CL json unmarshal failure", func(t *testing.T) {
		remoteCrypto2 := New(defaultKeystoreURL, client)

		remoteCrypto2.unmarshalFunc = failingUnmarshal

		var err error
		_, err = remoteCrypto2.Blind(bldKeyURL, map[string]interface{}{"attr1": 1, "attr2": "aaa"})
		require.Error(t, err)

		_, err = remoteCrypto2.GetCorrectnessProof(sgnKeyURL)
		require.Error(t, err)

		_, _, err = remoteCrypto2.SignWithSecrets(sgnKeyURL,
			map[string]interface{}{"attr1": 1, "attr2": "aaa"},
			secrets,
			secretsProof,
			[][]byte{offerNonce, requestNonce},
			"did:example:id",
		)
		require.Error(t, err)
	})
}

func processClRequest(w http.ResponseWriter, r *http.Request, sgnKh, bldKh *keyset.Handle) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	reqBody, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}

	if matchPath(r, blindURI) {
		err = clBlindPOSTHandle(w, reqBody, bldKh)
		if err != nil {
			return err
		}
	}

	if matchPath(r, correctnessProofURI) {
		err = clCorrectnessProofGETHandle(w, sgnKh)
		if err != nil {
			return err
		}
	}

	if matchPath(r, signWithSecretsURI) {
		err = clSignWithSecretsPOSTHandle(w, reqBody, sgnKh)
		if err != nil {
			return err
		}
	}

	return nil
}

func clBlindPOSTHandle(w http.ResponseWriter, reqBody []byte, kh *keyset.Handle) error {
	req := &blindReq{}

	err := json.Unmarshal(reqBody, req)
	if err != nil {
		return err
	}

	blinder, err := bld.NewBlinder(kh)
	if err != nil {
		return fmt.Errorf("create new CL blinder: %w", err)
	}

	defer blinder.Free() // nolint: errcheck

	vals := req.Values
	if len(vals) == 0 {
		vals = []map[string]interface{}{}
	}

	var blindeds [][]byte

	for _, val := range vals {
		blinded, e := blinder.Blind(val)
		if e != nil {
			return e
		}

		blindeds = append(blindeds, blinded)
	}

	resp := &blindResp{
		Blinded: blindeds,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func clCorrectnessProofGETHandle(w http.ResponseWriter, kh *keyset.Handle) error {
	signer, err := sgn.NewSigner(kh)
	if err != nil {
		return fmt.Errorf("create new CL signer: %w", err)
	}

	defer signer.Free() // nolint: errcheck

	correctnessProof, err := signer.GetCorrectnessProof()
	if err != nil {
		return fmt.Errorf("CL correctness proof msg: %w", err)
	}

	resp := &correctnessProofResp{
		CorrectnessProof: correctnessProof,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func clSignWithSecretsPOSTHandle(w http.ResponseWriter, reqBody []byte, kh *keyset.Handle) error {
	req := &signWithSecretsReq{}

	err := json.Unmarshal(reqBody, req)
	if err != nil {
		return err
	}

	signer, err := sgn.NewSigner(kh)
	if err != nil {
		return fmt.Errorf("create new CL signer: %w", err)
	}

	defer signer.Free() // nolint: errcheck

	signature, correctnessProof, err := signer.Sign(
		req.Values,
		req.Secrets,
		req.CorrectnessProof,
		req.Nonces,
		req.DID,
	)
	if err != nil {
		return fmt.Errorf("CL sign msg: %w", err)
	}

	resp := &signWithSecretsResp{
		Signature:        signature,
		CorrectnessProof: correctnessProof,
	}

	mResp, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	_, err = w.Write(mResp)
	if err != nil {
		return err
	}

	return nil
}

func generateBlindedSecretsWithNonces(
	t *testing.T,
	pubKey []byte,
	correctnessProof []byte,
	blindedVals []byte,
) ([]byte, []byte, []byte, []byte) {
	_pubKey, err := ursa.CredentialPublicKeyFromJSON(pubKey)
	require.NoError(t, err)
	_correctnessProof, err := ursa.CredentialKeyCorrectnessProofFromJSON(correctnessProof)
	require.NoError(t, err)
	_blindedVals, err := ursa.CredentialValuesFromJSON(blindedVals)
	require.NoError(t, err)

	_offerNonce, err := ursa.NewNonce()
	require.NoError(t, err)
	_blindedSecrets, err := ursa.BlindCredentialSecrets(_pubKey, _correctnessProof, _offerNonce, _blindedVals)
	require.NoError(t, err)
	_requestNonce, err := ursa.NewNonce()
	require.NoError(t, err)

	secrets, err := _blindedSecrets.Handle.ToJSON()
	require.NoError(t, err)
	secretsProof, err := _blindedSecrets.CorrectnessProof.ToJSON()
	require.NoError(t, err)
	offerNonce, err := _offerNonce.ToJSON()
	require.NoError(t, err)
	requestNonce, err := _requestNonce.ToJSON()
	require.NoError(t, err)

	return secrets, secretsProof, offerNonce, requestNonce
}
