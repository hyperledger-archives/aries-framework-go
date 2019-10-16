/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/DATA-DOG/godog"
	"github.com/go-openapi/swag"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-node/models"

	"github.com/hyperledger/aries-framework-go/test/dockerutil"
)

const sha2_256 = 18
const didDocNamespace = "did:sidetree:"

// DIDResolverSideTreeNodeSteps
type DIDResolverSideTreeNodeSteps struct {
	bddContext       *Context
	reqEncodedDIDDoc string
	resp             *httpRespone
}

// NewDIDResolverSteps
func NewDIDResolverSideTreeNodeSteps(context *Context) *DIDResolverSideTreeNodeSteps {
	return &DIDResolverSideTreeNodeSteps{bddContext: context}
}

func (d *DIDResolverSideTreeNodeSteps) createDIDDocument(sideTreeURL, didDocumentPath string) error {
	req := newCreateRequest(didDocumentPath)
	d.reqEncodedDIDDoc = swag.StringValue(req.Payload)
	var err error
	d.resp, err = sendRequest(sideTreeURL, req)
	return err
}

func (d *DIDResolverSideTreeNodeSteps) checkSuccessResp(msg string) error {
	if d.resp.errorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.errorMsg)
	}

	if msg == "#didID" {
		didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
		if err != nil {
			return err
		}
		msg = strings.Replace(msg, "#didID", didID, -1)
	}
	logger.Infof("check success resp %s contain %s", string(d.resp.payload), msg)
	if !strings.Contains(string(d.resp.payload), msg) {
		return fmt.Errorf("success resp %s doesn't contain %s", d.resp.payload, msg)
	}
	return nil
}

func (d *DIDResolverSideTreeNodeSteps) resolveDID(agentID string) error {
	didID, err := docutil.CalculateID(didDocNamespace, d.reqEncodedDIDDoc, sha2_256)
	if err != nil {
		return err
	}
	doc, err := d.bddContext.AgentCtx[agentID].DIDResolver().Resolve(didID)
	if err != nil {
		return err
	}
	if doc.ID != didID {
		return fmt.Errorf("resolved did ID %s not equal to %s", doc.ID, didID)
	}
	return nil
}

func (d *DIDResolverSideTreeNodeSteps) wait(seconds int) error {
	logger.Infof("Waiting [%d] seconds\n", seconds)
	time.Sleep(time.Duration(seconds) * time.Second)
	return nil
}

func newCreateRequest(didDocumentPath string) *models.Request {
	payload := encodeDidDocument(didDocumentPath)
	return &models.Request{
		Header: &models.Header{
			Operation: models.OperationTypeCreate, Alg: swag.String(""), Kid: swag.String("")},
		Payload:   swag.String(payload),
		Signature: swag.String("")}
}

func encodeDidDocument(didDocumentPath string) string {
	r, _ := os.Open(didDocumentPath)
	data, _ := ioutil.ReadAll(r)
	doc, _ := document.FromBytes(data)
	// add new key to make the document unique
	doc["unique"] = generateUUID()
	bytes, _ := doc.Bytes()
	return base64.URLEncoding.EncodeToString(bytes)
}

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

type httpRespone struct {
	payload  []byte
	errorMsg string
}

// sendRequest sends a regular POST request to the sidetree-node
// - If post request has operation "create" then return sidetree document else no response
func sendRequest(url string, req *models.Request) (*httpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}
	return handleHttpResp(resp)
}

func handleHttpResp(resp *http.Response) (*httpRespone, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}
	if status := resp.StatusCode; status != http.StatusOK {
		return &httpRespone{errorMsg: string(body)}, nil
	}
	return &httpRespone{payload: body}, nil
}

func sendHTTPRequest(url string, req *models.Request) (*http.Response, error) {
	client := &http.Client{}
	b, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}

	httpReq.Header.Set("Content-Type", "application/json")

	return client.Do(httpReq)
}

// RegisterSteps registers did exchange steps
func (d *DIDResolverSideTreeNodeSteps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to sidetree "([^"]*)" for create DID document "([^"]*)"`, d.createDIDDocument)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessResp)
	s.Step(`^"([^"]*)" agent resolve DID document$`, d.resolveDID)
	s.Step(`^we wait (\d+) seconds$`, d.wait)

}
