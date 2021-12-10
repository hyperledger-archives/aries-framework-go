/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
)

const (
	certPrefix        = "../../didcomm/transport/http/testdata/crypto/"
	clientTimeout     = 5 * time.Second
	controller        = "did:example:123456789"
	defaultKeyStoreID = "12345"
	defaultKID        = "99999"
)

func TestRemoteKeyStore(t *testing.T) {
	xRootCapabilityHeaderValue := []byte("DUMMY")

	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	pvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	marshalledPubKey := elliptic.Marshal(pvKey.PublicKey.Curve, pvKey.PublicKey.X, pvKey.PublicKey.Y)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTRequest(w, r, defaultKeyStoreID, defaultKID, marshalledPubKey)
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	t.Run("CreateKeyStore failures", func(t *testing.T) {
		blankClient := &http.Client{}
		_, _, err = CreateKeyStore(blankClient, url, controller, "", nil)
		require.Contains(t, err.Error(), "posting Create keystore failed")

		_, _, err = CreateKeyStore(blankClient, "``#$%", controller, "", nil)
		require.EqualError(t, err, "build request for Create keystore error: parse \"``#$%/v1/keystores\": "+
			"invalid URL escape \"%/v\"")
	})

	t.Run("CreateKeyStore API error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		_, _, err = CreateKeyStore(_client, _url, controller, "", nil)
		require.Contains(t, err.Error(), "api error msg")
	})

	t.Run("CreateKeyStore json error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`[]`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		_, _, err = CreateKeyStore(_client, _url, controller, "", nil)
		require.Contains(t, err.Error(), "cannot unmarshal array into Go value")
	})

	t.Run("CreateKeyStore json marshal failure", func(t *testing.T) {
		_, _, err = CreateKeyStore(client, url, controller, "", nil, WithMarshalFn(failingMarshal))
		require.Contains(t, err.Error(), "failed to marshal Create keystore request")
		require.Contains(t, err.Error(), "failingMarshal always fails")
	})

	t.Run("CreateKeyStore success", func(t *testing.T) {
		ksID, capability, e := CreateKeyStore(client, url, controller, "vaultID", []byte("capability"))
		require.NoError(t, e)
		require.Equal(t, capability, xRootCapabilityHeaderValue)
		require.EqualValues(t, defaultKeystoreURL, ksID)
	})

	t.Run("Create API error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		tmpKMS := New(_url, _client)

		_, _, err = tmpKMS.Create(kms.ED25519Type)
		require.Contains(t, err.Error(), "api error msg")
	})

	t.Run("Create Key failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpKMS := New(defaultKeystoreURL, blankClient)

		_, _, err = tmpKMS.Create(kms.ED25519Type)
		require.Contains(t, err.Error(), "posting Create key failed")

		_, _, err = tmpKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.Contains(t, err.Error(), "posting Create key failed")

		tmpKMS = New("``#$%", blankClient)
		_, _, err = tmpKMS.Create(kms.ED25519Type)
		require.EqualError(t, err, "posting Create key failed [``#$%/keys, build post request error: parse"+
			" \"``#$%/keys\": invalid URL escape \"%/k\"]")
	})

	t.Run("New, Create, Get, Export/Import success, all other functions should fail", func(t *testing.T) {
		remoteKMS := New(defaultKeystoreURL, client)

		kid, keyURL, err := remoteKMS.Create(kms.ED25519Type)
		require.NoError(t, err)
		require.Equal(t, defaultKID, kid)
		require.Contains(t, keyURL, fmt.Sprintf("%s/keys/%s", defaultKeystoreURL, defaultKID))

		t.Run("CreateKey json marshal failure", func(t *testing.T) {
			remoteKMS2 := New(defaultKeystoreURL, client)

			remoteKMS2.marshalFunc = failingMarshal
			_, _, err = remoteKMS2.Create(kms.ED25519Type)
			require.Contains(t, err.Error(), "failed to marshal Create key request")
			require.Contains(t, err.Error(), "failingMarshal always fails")
		})

		kh, err := remoteKMS.Get(kid)
		require.NoError(t, err)
		require.EqualValues(t, keyURL, kh)

		pubKey, err := remoteKMS.ExportPubKeyBytes(kid)
		require.NoError(t, err)
		require.EqualValues(t, marshalledPubKey, pubKey)

		t.Run("ExportPubKeyBytes API error", func(t *testing.T) {
			_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
				require.NoError(t, err)
			})

			srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

			defer func() { require.NoError(t, srv.Close()) }()

			tmpKMS := New(_url, _client)

			_, err = tmpKMS.ExportPubKeyBytes("kid")
			require.Contains(t, err.Error(), "api error msg")
		})

		t.Run("ExportPubKeyBytes json unmarshal failure", func(t *testing.T) {
			remoteKMS3 := New(defaultKeystoreURL, client)

			kid1, keyURL1, e := remoteKMS3.Create(kms.ED25519Type)
			require.NoError(t, e)
			require.Equal(t, defaultKID, kid1)
			require.Contains(t, keyURL1, fmt.Sprintf("%s/keys/%s", defaultKeystoreURL, defaultKID))

			// switch the marshaller in remoteKMS3 to force an error in ExportPubKeyBytes
			remoteKMS3.unmarshalFunc = failingUnmarshal
			_, err = remoteKMS3.ExportPubKeyBytes(kid1)
			require.Contains(t, err.Error(), "unmarshal failed")
			require.Contains(t, err.Error(), "failingUnmarshal always fails")

			remoteKMS3.unmarshalFunc = json.Unmarshal

			t.Logf("kid1 : %v", kid1)

			// test GET http function failure
			remoteKMS3.keystoreURL = "``#$%"
			_, err = remoteKMS3.ExportPubKeyBytes(kid1)
			require.Contains(t, err.Error(), "posting GET ExportPubKeyBytes key failed")
			require.Contains(t, err.Error(), "build get request error")
		})

		nKID, _, err := remoteKMS.CreateAndExportPubKeyBytes(kms.AES128GCMType)
		require.NoError(t, err)
		require.Equal(t, kid, nKID)

		t.Run("ExportPubKeyBytes should fail with bad http client", func(t *testing.T) {
			blankClient := &http.Client{}
			remoteKMS2 := New(defaultKeystoreURL, blankClient)

			_, err = remoteKMS2.ExportPubKeyBytes(kid)
			require.Contains(t, err.Error(), "posting GET ExportPubKeyBytes key failed")
		})

		_, _, err = remoteKMS.Rotate(kms.AES128GCMType, "")
		require.EqualError(t, err, "function Rotate is not implemented in remoteKMS")

		_, err = remoteKMS.PubKeyBytesToHandle(nil, kms.AES128GCMType)
		require.EqualError(t, err, "function PubKeyBytesToHandle is not implemented in remoteKMS")
	})
}

func TestCreateKeyWithLocationInResponseBody(t *testing.T) {
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTRequestForCreateWithResponseBody(w, r, defaultKeyStoreID, defaultKID)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	remoteKMS := New(defaultKeystoreURL, client)

	kid1, keyURL1, err := remoteKMS.Create(kms.ED25519Type)
	require.NoError(t, err)
	require.Equal(t, defaultKID, kid1)
	require.Contains(t, keyURL1, fmt.Sprintf("%s/keys/%s", defaultKeystoreURL, defaultKID))

	remoteKMS.unmarshalFunc = failingUnmarshal
	_, _, err = remoteKMS.Create(kms.ED25519Type)
	require.Contains(t, err.Error(), "unmarshal failed")
	require.Contains(t, err.Error(), "failingUnmarshal always fails")
}

func TestRemoteKeyStoreWithHeadersFunc(t *testing.T) {
	xRootCapabilityHeaderValue := []byte("DUMMY")

	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	pvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	marshalledPubKey := elliptic.Marshal(pvKey.PublicKey.Curve, pvKey.PublicKey.X, pvKey.PublicKey.Y)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTRequest(w, r, defaultKeyStoreID, defaultKID, marshalledPubKey)
		w.WriteHeader(http.StatusCreated)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	t.Run("CreateKeyStore with http header opt success", func(t *testing.T) {
		ksID, capability, e := CreateKeyStore(client, url, controller, "vaultID", []byte("capability"),
			WithHeaders(mockAddHeadersFuncSuccess), WithCache(1))
		require.NoError(t, e)
		require.Equal(t, capability, xRootCapabilityHeaderValue)
		require.EqualValues(t, defaultKeystoreURL, ksID)
	})

	t.Run("CreateKeyStore with http header opt failure", func(t *testing.T) {
		_, _, e := CreateKeyStore(client, url, controller, "vaultID", []byte("capability"),
			WithHeaders(mockAddHeadersFuncError))
		require.EqualError(t, e, fmt.Errorf("add optional request headers error: %w", errAddHeadersFunc).Error())
	})

	t.Run("test New with valid http header func option", func(t *testing.T) {
		remoteKMS := New(defaultKeystoreURL, client, WithHeaders(mockAddHeadersFuncSuccess))

		kid, keyURL, e := remoteKMS.Create(kms.ED25519Type)
		require.NoError(t, e)
		require.Equal(t, defaultKID, kid)
		require.Contains(t, keyURL, fmt.Sprintf("/v1/keystores/%s/keys/%s", defaultKeyStoreID, defaultKID))
	})

	t.Run("test New with invalid http header func option", func(t *testing.T) {
		remoteKMS := New(defaultKeystoreURL, client, WithHeaders(mockAddHeadersFuncError))

		_, _, err = remoteKMS.Create(kms.ED25519Type)
		require.EqualError(t, err, fmt.Errorf("posting Create key failed [%s/keys, add optional request "+
			"headers error: %w]", defaultKeystoreURL, errAddHeadersFunc).Error())
	})
}

func TestImportPrivateKey(t *testing.T) {
	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err = processPOSTRequestForImportKey(w, r, defaultKeyStoreID, defaultKID)
		require.NoError(t, err)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)
	defaultKeystoreURL := fmt.Sprintf("%s/%s", strings.ReplaceAll(KeystoreEndpoint,
		"{serverEndpoint}", url), defaultKeyStoreID)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	remoteKMS := New(defaultKeystoreURL, client)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	keyID, keyURL, err := remoteKMS.ImportPrivateKey(privateKey, kms.ED25519Type)
	require.NoError(t, err)
	require.Equal(t, defaultKID, keyID)
	require.Contains(t, keyURL, fmt.Sprintf("%s/keys/%s", defaultKeystoreURL, defaultKID))

	_, _, err = remoteKMS.ImportPrivateKey([]byte("invalid key bytes"), kms.ED25519Type)
	require.Contains(t, err.Error(), "failed to marshal private key")

	remoteKMS.marshalFunc = failingMarshal

	_, _, err = remoteKMS.ImportPrivateKey(privateKey, kms.ED25519Type)
	require.Contains(t, err.Error(), "failed to marshal ImportKey request")
	require.Contains(t, err.Error(), "failingMarshal always fails")

	remoteKMS.marshalFunc = json.Marshal

	remoteKMS.unmarshalFunc = failingUnmarshal

	_, _, err = remoteKMS.ImportPrivateKey(privateKey, kms.ED25519Type)
	require.Contains(t, err.Error(), "unmarshal failed")
	require.Contains(t, err.Error(), "failingUnmarshal always fails")

	remoteKMS.unmarshalFunc = json.Unmarshal

	t.Run("ImportPrivateKey API error", func(t *testing.T) {
		_hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, err = w.Write([]byte(`{"errMessage": "api error msg"}`))
			require.NoError(t, err)
		})

		srv, _url, _client := CreateMockHTTPServerAndClient(t, _hf)

		defer func() { require.NoError(t, srv.Close()) }()

		tmpKMS := New(_url, _client)

		_, _, err = tmpKMS.ImportPrivateKey(privateKey, kms.ED25519Type)
		require.Contains(t, err.Error(), "api error msg")
	})
}

func TestCloseResponseBody(t *testing.T) {
	closeResponseBody(&errFailingCloser{}, logger, "testing close fail should log: errFailingCloser always fails")
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, keysetID, kid string,
	defaultExportPubKey []byte) error {
	xRootCapabilityHeaderValue := []byte("DUMMY")

	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	if strings.LastIndex(r.URL.Path, "/keys") == len(r.URL.Path)-len("/keys") {
		return processCreateKeyRequest(w, r, keysetID, kid, defaultExportPubKey)
	}

	if strings.LastIndex(r.URL.Path, "/export") == len(r.URL.Path)-len("/export") {
		return processExportKeyRequest(w, defaultExportPubKey)
	}

	resp := &createKeyStoreResp{
		KeyStoreURL: fmt.Sprintf("https://%s/v1/keystores/%s", r.Host, keysetID),
		Capability:  xRootCapabilityHeaderValue,
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

func processCreateKeyRequest(w http.ResponseWriter, r *http.Request, keysetID, kid string,
	defaultExportPubKey []byte) error {
	var req createKeyReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		return err
	}

	resp := &createKeyResp{
		KeyURL:    fmt.Sprintf("https://%s/v1/keystores/%s/keys/%s", r.Host, keysetID, kid),
		PublicKey: defaultExportPubKey,
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

func processExportKeyRequest(w io.Writer, defaultExportPubKey []byte) error {
	resp := &exportKeyResp{
		PublicKey: defaultExportPubKey,
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

func processPOSTRequestForCreateWithResponseBody(w http.ResponseWriter, r *http.Request, keysetID, kid string) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	locationHeaderURL := "https://" + r.Host + "/v1/keystores/" + keysetID

	if strings.LastIndex(r.URL.Path, "/keys") == len(r.URL.Path)-len("/keys") {
		locationHeaderURL += "/keys/" + kid

		resp := &createKeyResp{
			KeyURL: locationHeaderURL,
		}

		mResp, err := json.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(mResp)
		if err != nil {
			return err
		}
	}

	return nil
}

func processPOSTRequestForImportKey(w http.ResponseWriter, r *http.Request, keysetID, kid string) error {
	if valid := validateHTTPMethod(w, r); !valid {
		return errors.New("http method invalid")
	}

	if valid := validatePostPayload(r, w); !valid {
		return errors.New("http request body invalid")
	}

	locationHeaderURL := "https://" + r.Host + "/v1/keystores/" + keysetID

	if strings.LastIndex(r.URL.Path, "/keys") == len(r.URL.Path)-len("/keys") {
		locationHeaderURL += "/keys/" + kid

		resp := &importKeyResp{
			KeyURL: locationHeaderURL,
		}

		mResp, err := json.Marshal(resp)
		if err != nil {
			return err
		}

		_, err = w.Write(mResp)
		if err != nil {
			return err
		}
	}

	return nil
}

// validateHTTPMethod validate HTTP method and content-type.
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodGet:
	default:
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != ContentType && r.Method == http.MethodPost {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

// validatePayload validate and get the payload from the request.
func validatePostPayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 && r.Method == http.MethodPost { // empty payload should not be accepted for POST request
		http.Error(w, "Empty payload", http.StatusBadRequest)
		return false
	}

	return true
}

// CreateMockHTTPServerAndClient creates mock http server and client using tls and returns them.
func CreateMockHTTPServerAndClient(t *testing.T, inHandler http.Handler) (net.Listener, string, *http.Client) {
	server := startMockServer(inHandler)
	port := getServerPort(server)
	serverURL := fmt.Sprintf("https://localhost:%d", port)

	// build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{ //nolint:gosec
		RootCAs:      cp,
		Certificates: nil,
	}

	// create an http client to communicate with the server that has our inbound handlers set above
	client := &http.Client{
		Timeout: clientTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	return server, serverURL, client
}

func startMockServer(handler http.Handler) net.Listener {
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		logger.Fatalf("HTTP listener failed to start: %s", err)
	}

	go func() {
		err := http.ServeTLS(listener, handler, certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			logger.Fatalf("HTTP server failed to start: %s", err)
		}
	}()

	return listener
}

func getServerPort(server net.Listener) int {
	// read dynamic port assigned to the server to be used by the client
	return server.Addr().(*net.TCPAddr).Port
}

func addCertsToCertPool(pool *x509.CertPool) error {
	var rawCerts []string

	// add contents of ec-pubCert(1, 2 and 3).pem to rawCerts
	for i := 1; i <= 3; i++ {
		certPath := fmt.Sprintf("%sec-pubCert%d.pem", certPrefix, i)
		// Create a pool with server certificates
		cert, e := ioutil.ReadFile(filepath.Clean(certPath))
		if e != nil {
			return fmt.Errorf("reading certificate failed: %w", e)
		}

		rawCerts = append(rawCerts, string(cert))
	}

	certs := decodeCerts(rawCerts)
	for i := range certs {
		pool.AddCert(certs[i])
	}

	return nil
}

// decodeCerts will decode a list of pemCertsList (string) into a list of x509 certificates.
func decodeCerts(pemCertsList []string) []*x509.Certificate {
	var certs []*x509.Certificate

	for _, pemCertsString := range pemCertsList {
		pemCerts := []byte(pemCertsString)
		for len(pemCerts) > 0 {
			var block *pem.Block

			block, pemCerts = pem.Decode(pemCerts)
			if block == nil {
				break
			}

			if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
				continue
			}

			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			certs = append(certs, cert)
		}
	}

	return certs
}

var errFailingMarshal = errors.New("failingMarshal always fails")

func failingMarshal(interface{}) ([]byte, error) {
	return nil, errFailingMarshal
}

var errFailingUnmarshal = errors.New("failingUnmarshal always fails")

func failingUnmarshal([]byte, interface{}) error {
	return errFailingUnmarshal
}

type errFailingCloser struct{}

func (c *errFailingCloser) Close() error {
	return errors.New("errFailingCloser always fails")
}

func mockAddHeadersFuncSuccess(req *http.Request) (*http.Header, error) {
	// mocking a call to an auth server to get necessary credentials.
	// It only sets mock http.Header entries for testing purposes.
	req.Header.Set("controller", "mockController")
	req.Header.Set("authServerURL", "mockAuthServerURL")
	req.Header.Set("secret", "mockSecret")

	return &req.Header, nil
}

var errAddHeadersFunc = errors.New("mockAddHeadersFuncError always fails")

func mockAddHeadersFuncError(_ *http.Request) (*http.Header, error) {
	return nil, errAddHeadersFunc
}
