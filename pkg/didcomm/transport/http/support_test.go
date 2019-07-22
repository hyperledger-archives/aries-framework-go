/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const certPrefix = "testdata/crypto/"
const clientTimeout = 1 * time.Second

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

func startMockServer(handler http.Handler) net.Listener {
	// ":0" will make the listener auto assign a free port
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Fatalf("HTTP listener failed to start: %s", err)
	}
	go func() {
		err := http.ServeTLS(listener, handler, certPrefix+"ec-pubCert1.pem", certPrefix+"ec-key1.pem")
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

func getServerPort(server net.Listener) int {
	// read dynamic port assigned to the server to be used by the client
	return server.Addr().(*net.TCPAddr).Port
}
