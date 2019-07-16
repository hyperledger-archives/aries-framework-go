/*
	Copyright SecureKey Technologies Inc. All Rights Reserved.

	SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
)

const certPrefix = "testdata/crypto/"
const clientTimeout = 1 * time.Second

func TestWithOutboundOpts(t *testing.T) {
	opt := WithOutboundHTTPClient(nil)
	require.NotNil(t, opt)
	clOpts := &outboundCommHTTPOpts{}
	opt(clOpts)

	opt = WithOutboundTimeout(clientTimeout)
	require.NotNil(t, opt)
	clOpts = &outboundCommHTTPOpts{}
	// opt.client is nil, so setting timeout should panic
	require.Panics(t, func() { opt(clOpts) })

	opt = WithOutboundTLSConfig(nil)
	require.NotNil(t, opt)
	clOpts = &outboundCommHTTPOpts{}
	opt(clOpts)
}

func TestOutboundHTTPTransport(t *testing.T) {
	// prepare http server
	server := startMockServer()
	// read dynamic port assigned to the server to be used by the client
	port := server.Addr().(*net.TCPAddr).Port
	serverUrl := fmt.Sprintf("https://localhost:%d", port)
	defer func() {
		err := server.Close()
		if err != nil {
			log.Fatalf("Failed to stop server: %s", err)
		}
	}()

	//build a mock cert pool
	cp := x509.NewCertPool()
	err := addCertsToCertPool(cp)
	require.NoError(t, err)

	// build a tls.Config instance to be used by the outbound transport
	tlsConfig := &tls.Config{
		RootCAs:      cp,
		Certificates: nil,
	}
	// create a new invalid Outbound transport instance
	ot, err := NewOutbound()
	require.Error(t, err)
	require.EqualError(t, err, "Can't create an outbound transport without an HTTP client")

	// now create a new valid Outbound transport instance and test its Send() call
	ot, err = NewOutbound(WithOutboundTLSConfig(tlsConfig), WithOutboundTimeout(clientTimeout))
	require.NoError(t, err)
	require.NotNil(t, ot)

	// test Outbound transport's api
	// first with an empty url
	r, e := ot.Send("Hello World", "")
	require.Error(t, e)
	require.Empty(t, r)

	// now try a bad url
	r, e = ot.Send("Hello World", "https://badurl")
	require.Error(t, e)
	require.Empty(t, r)

	// and try with a 'bad' payload with a valid url..
	r, e = ot.Send("bad", serverUrl)
	require.Error(t, e)
	require.Empty(t, r)

	// finally using a valid url
	r, e = ot.Send("Hello World", serverUrl)
	require.NoError(t, e)
	require.NotEmpty(t, r)

}

func addCertsToCertPool(pool *x509.CertPool) error {
	var rawCerts []string

	// add contents of ec-pubCert(1, 2 and 3).pem to rawCerts
	for i := 1; i <= 3; i++ {
		certPath := fmt.Sprintf("%sec-pubCert%d.pem", certPrefix, i)
		// Create a pool with server certificates
		cert, e := ioutil.ReadFile(filepath.Clean(certPath))
		if e != nil {
			return errors.Wrap(e, "Failed Reading certificate")
		}
		rawCerts = append(rawCerts, string(cert))
	}

	certs := decodeCerts(rawCerts)
	for i := range certs {
		pool.AddCert(certs[i])
	}
	return nil
}

func startMockServer() net.Listener {
	testHandler := mockHttpHandler{}
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("HTTP listener failed to start: %s", err)
	}
	go func() {
		err := http.ServeTLS(listener, testHandler, certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
		if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
			log.Fatalf("HTTP server failed to start: %s", err)
		}
	}()
	return listener
}

type mockHttpHandler struct {
}

func (m mockHttpHandler) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	if req.Body != nil {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil || string(body) == "bad" {
			res.WriteHeader(http.StatusBadRequest)
			_, _ = res.Write([]byte(fmt.Sprintf("bad request: %s", body)))
			return
		}
	}

	// mocking successful response
	res.WriteHeader(http.StatusAccepted) // usually DID-Comm expects StatusAccepted code (202)
	res.Write([]byte("success"))
}

// decodeCerts will decode a list of pemCertsList (string) into a list of x509 certificates
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
