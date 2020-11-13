/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package webkms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/hyperledger/aries-framework-go/pkg/kms"
	"github.com/hyperledger/aries-framework-go/pkg/mock/storage"
)

const (
	certPrefix    = "../../didcomm/transport/http/testdata/crypto/"
	clientTimeout = 5 * time.Second
)

func TestRemoteKeyStore(t *testing.T) {
	storeProvider := storage.NewMockStoreProvider()
	controller := "did:example:123456789"
	defaultKeyStoreID := "12345"
	defaultKID := "99999"

	secret := make([]byte, 10)
	_, err := rand.Read(secret)
	require.NoError(t, err)

	pvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	marshalledPubKey := elliptic.Marshal(pvKey.PublicKey.Curve, pvKey.PublicKey.X, pvKey.PublicKey.Y)
	defaultExportPubKey := base64.URLEncoding.EncodeToString(marshalledPubKey)

	hf := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		processPOSTRequest(w, r, defaultKeyStoreID, defaultKID, defaultExportPubKey)
	})

	server, url, client := CreateMockHTTPServerAndClient(t, hf)

	defer func() {
		e := server.Close()
		require.NoError(t, e)
	}()

	t.Run("CreateKeyStore failures", func(t *testing.T) {
		blankClient := &http.Client{}
		_, err = CreateKeyStore(storeProvider.Store, blankClient, url, controller, secret, json.Marshal)
		require.Contains(t, err.Error(), "posting Create keystore failed")

		badStore := &storage.MockStore{
			ErrPut: errors.New("bad Put operation"),
		}

		_, err = CreateKeyStore(badStore, client, url, controller, secret, json.Marshal)
		require.Contains(t, err.Error(), "bad Put operation")
	})

	t.Run("CreateKeyStore json marshal failure", func(t *testing.T) {
		_, err = CreateKeyStore(storeProvider.Store, client, url, controller, secret, failingMarshal)
		require.Contains(t, err.Error(), "failed to marshal Create keystore request")
		require.Contains(t, err.Error(), "failingMarshal always fails")
	})

	t.Run("CreateKeyStore success", func(t *testing.T) {
		ksID, err := CreateKeyStore(storeProvider.Store, client, url, controller, secret, json.Marshal)
		require.NoError(t, err)
		require.EqualValues(t, storeProvider.Store.Store[KeystoreURLField], ksID)
	})

	t.Run("new remoteKMS instance creation failure", func(t *testing.T) {
		badStoreProvider := &storage.MockStoreProvider{
			ErrOpenStoreHandle: errors.New("failed to open remoteKMS store"),
		}

		_, err := New(badStoreProvider, client, json.Marshal)
		require.EqualError(t, err, "failed to open remoteKMS store")

		badStore := &storage.MockStore{
			ErrGet: errors.New("bad Get operation"),
		}

		_, err = New(storage.NewCustomMockStoreProvider(badStore), client, json.Marshal)
		require.EqualError(t, err, "failed to fetch keystore url from remoteKMS config storage: bad Get operation")
	})

	t.Run("Create Key failure", func(t *testing.T) {
		blankClient := &http.Client{}
		tmpKMS, err := New(storeProvider, blankClient, json.Marshal)
		require.NoError(t, err)

		_, _, err = tmpKMS.Create(kms.ED25519Type)
		require.Contains(t, err.Error(), "posting Create key failed")

		_, _, err = tmpKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.Contains(t, err.Error(), "posting Create key failed")
	})

	t.Run("read from remote kms configStore failure", func(t *testing.T) {
		remoteKMS, err := New(storeProvider, client, json.Marshal)
		require.NoError(t, err)

		badStore := &storage.MockStore{
			ErrGet: errors.New("bad Get operation"),
		}

		remoteKMS.configStore = badStore

		_, err = remoteKMS.Get("")
		require.EqualError(t, err, "bad Get operation")

		_, err = remoteKMS.ExportPubKeyBytes("")
		require.EqualError(t, err, "bad Get operation")

		_, _, err = remoteKMS.CreateAndExportPubKeyBytes(kms.ED25519Type)
		require.EqualError(t, err, "bad Get operation")
	})

	t.Run("New, Create, Get and export success, all other functions not implemented should "+
		"fail", func(t *testing.T) {
		remoteKMS, err := New(storeProvider, client, json.Marshal)
		require.NoError(t, err)

		kid, keyURL, err := remoteKMS.Create(kms.ED25519Type)
		require.NoError(t, err)
		require.Equal(t, defaultKID, kid)
		require.Contains(t, keyURL, fmt.Sprintf("/kms/keystores/%s/keys/%s", defaultKeyStoreID, defaultKID))

		t.Run("CreateKey json marshal failure", func(t *testing.T) {
			remoteKMS2, e := New(storeProvider, client, failingMarshal)
			require.NoError(t, e)

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

		t.Run("ExportPubKeyBytes json marshal failure", func(t *testing.T) {
			remoteKMS3, e := New(storeProvider, client, json.Marshal)
			require.NoError(t, e)

			kid1, keyURL1, e := remoteKMS3.Create(kms.ED25519Type)
			require.NoError(t, e)
			require.Equal(t, defaultKID, kid1)
			require.Contains(t, keyURL1, fmt.Sprintf("/kms/keystores/%s/keys/%s", defaultKeyStoreID, defaultKID))

			// switch the marshaller in remoteKMS3 to force an error in ExportPubKeyBytes
			remoteKMS3.marshalFunc = failingMarshal
			_, err = remoteKMS3.ExportPubKeyBytes(kid1)
			require.Contains(t, err.Error(), "failed to marshal ExportPubKeyBytes key request")
			require.Contains(t, err.Error(), "failingMarshal always fails")
		})

		nKID, _, err := remoteKMS.CreateAndExportPubKeyBytes(kms.AES128GCMType)
		require.NoError(t, err)
		require.Equal(t, kid, nKID)

		t.Run("ExportPubKeyBytes should fail with bad http client", func(t *testing.T) {
			blankClient := &http.Client{}
			remoteKMS2, e := New(storeProvider, blankClient, json.Marshal)
			require.NoError(t, e)

			_, err = remoteKMS2.ExportPubKeyBytes(kid)
			require.Contains(t, err.Error(), "posting ExportPubKeyBytes key failed")
		})

		_, _, err = remoteKMS.Rotate(kms.AES128GCMType, "")
		require.EqualError(t, err, "function Rotate is not implemented in remoteKMS")

		_, err = remoteKMS.PubKeyBytesToHandle(nil, kms.AES128GCMType)
		require.EqualError(t, err, "function PubKeyBytesToHandle is not implemented in remoteKMS")

		_, _, err = remoteKMS.ImportPrivateKey(nil, kms.AES128GCMType)
		require.EqualError(t, err, "function ImportPrivateKey is not implemented in remoteKMS")
	})
}

func TestCloseResponseBody(t *testing.T) {
	closeResponseBody(&errFailingCloser{}, logger, "testing close fail should log: errFailingCloser always fails")
}

func processPOSTRequest(w http.ResponseWriter, r *http.Request, keysetID, kid, defaultExportPubKey string) {
	if valid := validateHTTPMethod(w, r); !valid {
		return
	}

	if valid := validatePayload(r, w); !valid {
		return
	}

	locationHeaderURL := "https://" + r.Host + "/kms/keystores/" + keysetID

	if strings.LastIndex(r.URL.Path, "/keys") == len(r.URL.Path)-len("/keys") {
		locationHeaderURL += "/keys/" + kid
	}

	w.Header().Add(LocationHeader, locationHeaderURL)

	if strings.LastIndex(r.URL.Path, "/export") == len(r.URL.Path)-len("/export") {
		w.Header().Add(KeyBytesHeader, defaultExportPubKey)
	}
}

// validateHTTPMethod validate HTTP method and content-type.
func validateHTTPMethod(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" {
		http.Error(w, "HTTP Method not allowed", http.StatusMethodNotAllowed)
		return false
	}

	ct := r.Header.Get("Content-type")
	if ct != ContentType {
		http.Error(w, fmt.Sprintf("Unsupported Content-type \"%s\"", ct), http.StatusUnsupportedMediaType)
		return false
	}

	return true
}

// validatePayload validate and get the payload from the request.
func validatePayload(r *http.Request, w http.ResponseWriter) bool {
	if r.ContentLength == 0 { // empty payload should not be accepted
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

type errFailingCloser struct{}

func (c *errFailingCloser) Close() error {
	return errors.New("errFailingCloser always fails")
}
