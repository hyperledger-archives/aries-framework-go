/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package didresolver

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cucumber/godog"
	"github.com/trustbloc/sidetree-core-go/pkg/document"
	"github.com/trustbloc/sidetree-core-go/pkg/docutil"
	"github.com/trustbloc/sidetree-core-go/pkg/restapi/model"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	diddoc "github.com/hyperledger/aries-framework-go/pkg/doc/did"
	vdriapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/vdri"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
)

const (
	sha2_256        = 18
	didDocNamespace = "did:sidetree"
	maxRetry        = 10
)

var logger = log.New("aries-framework/didresolver-tests")

// Steps for DID resolver tests
type Steps struct {
	bddContext    *bddctx.BDDContext
	createPayload string
	resp          *httpRespone
}

// NewDIDResolverSteps returns new steps for DID resolver tests
func NewDIDResolverSteps(ctx *bddctx.BDDContext) *Steps {
	return &Steps{bddContext: ctx}
}

func (d *Steps) createDIDDocument(agents, method string) error {
	for _, agentID := range strings.Split(agents, ",") {
		doc, err := d.bddContext.AgentCtx[agentID].VDRIRegistry().Create(method,
			vdriapi.WithRequestBuilder(buildSideTreeRequest))
		if err != nil {
			return fmt.Errorf("[%s] %v", agents, err)
		}

		d.bddContext.PublicDIDs[agentID] = doc
	}

	return nil
}

// CreateDIDDocument creates DIDDocument
func CreateDIDDocument(ctx *bddctx.BDDContext, agents, method string) error {
	return (&Steps{bddContext: ctx}).createDIDDocument(agents, method)
}

func (d *Steps) createDIDDocumentFromFile(sideTreeURL, didDocumentPath string) error {
	encodedDoc := encodeDidDocument(d.didDocFromFile(didDocumentPath))

	encodedPayload, err := getCreatePayload(encodedDoc)
	if err != nil {
		return err
	}

	d.createPayload = encodedPayload

	req := newCreateRequest(encodedPayload)
	d.resp, err = sendRequest(d.bddContext.Args[sideTreeURL], req)

	return err
}

func (d *Steps) checkSuccessResp(msg string) error {
	if d.resp.errorMsg != "" {
		return fmt.Errorf("error resp %s", d.resp.errorMsg)
	}

	if msg == "#didID" {
		didID, err := docutil.CalculateID(didDocNamespace, d.createPayload, sha2_256)
		if err != nil {
			return err
		}

		msg = strings.ReplaceAll(msg, "#didID", didID)
	}

	logger.Debugf("check success resp %s contain %s", string(d.resp.payload), msg)

	if !strings.Contains(string(d.resp.payload), msg) {
		return fmt.Errorf("success resp %s doesn't contain %s", d.resp.payload, msg)
	}

	return nil
}

func (d *Steps) resolveDID(agentID string) error {
	didID, err := docutil.CalculateID(didDocNamespace, d.createPayload, sha2_256)
	if err != nil {
		return err
	}

	doc, err := resolveDID(d.bddContext.AgentCtx[agentID].VDRIRegistry(), didID, maxRetry)
	if err != nil {
		return err
	}

	if doc.ID != didID {
		return fmt.Errorf("resolved did ID %s not equal to %s", doc.ID, didID)
	}

	return nil
}

func (d *Steps) didDocFromFile(didDocumentPath string) *document.Document {
	r, err := os.Open(d.bddContext.Args[didDocumentPath])
	if err != nil {
		logger.Errorf("Failed to open document, %s", err)
	}

	data, err := ioutil.ReadAll(r)
	if err != nil {
		logger.Errorf("Failed to read document, %s", err)
	}

	doc, err := document.FromBytes(data)
	if err != nil {
		logger.Errorf("Failed to get bytes from document, %s", err)
	}

	// add new key to make the document unique
	doc["unique"] = generateUUID()

	return &doc
}

func newCreateRequest(payload string) *model.Request {
	return &model.Request{
		Protected: &model.Header{Alg: "", Kid: ""},
		Payload:   payload,
		Signature: ""}
}

func getCreatePayload(encodedDoc string) (string, error) {
	schema := createPayloadSchema{
		Operation:           model.OperationTypeCreate,
		DidDocument:         encodedDoc,
		NextUpdateOTPHash:   "",
		NextRecoveryOTPHash: "",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(payload), nil
}

func encodeDidDocument(doc *document.Document) string {
	b, err := doc.Bytes()
	if err != nil {
		logger.Errorf("Failed to get bytes from document, %s", err)
	}

	return base64.URLEncoding.EncodeToString(b)
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
func sendRequest(url string, req *model.Request) (*httpRespone, error) {
	resp, err := sendHTTPRequest(url, req)
	if err != nil {
		return nil, err
	}

	return handleHTTPResp(resp)
}

func handleHTTPResp(resp *http.Response) (*httpRespone, error) {
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body failed: %w", err)
	}

	if status := resp.StatusCode; status != http.StatusOK {
		return &httpRespone{errorMsg: string(body)}, nil
	}

	return &httpRespone{payload: body}, nil
}

func sendHTTPRequest(url string, req *model.Request) (*http.Response, error) {
	client := &http.Client{}

	b, err := json.Marshal(req)
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

func resolveDID(vdriRegistry vdriapi.Registry, did string, maxRetry int) (*diddoc.Doc, error) {
	var doc *diddoc.Doc

	var err error
	for i := 1; i <= maxRetry; i++ {
		doc, err = vdriRegistry.Resolve(did)
		if err == nil || !strings.Contains(err.Error(), "DID does not exist") {
			return doc, err
		}

		time.Sleep(1 * time.Second)
		logger.Debugf("Waiting for public did to be published in sidtree: %d second(s)\n", i)
	}

	return doc, err
}

// buildSideTreeRequest request builder for sidetree public DID creation
func buildSideTreeRequest(docBytes []byte) (io.Reader, error) {
	encodeDidDocument := base64.URLEncoding.EncodeToString(docBytes)

	schema := createPayloadSchema{
		Operation:           model.OperationTypeCreate,
		DidDocument:         encodeDidDocument,
		NextUpdateOTPHash:   "",
		NextRecoveryOTPHash: "",
	}

	payload, err := json.Marshal(schema)
	if err != nil {
		return nil, err
	}

	request := &model.Request{
		Protected: &model.Header{Alg: "", Kid: ""},
		Payload:   base64.URLEncoding.EncodeToString(payload),
		Signature: ""}

	b, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}

	return bytes.NewReader(b), nil
}

// createPayloadSchema is the struct for create payload
type createPayloadSchema struct {

	// operation
	Operation model.OperationType `json:"type"`

	// Encoded original DID document
	DidDocument string `json:"didDocument"`

	// Hash of the one-time password for the next update operation
	NextUpdateOTPHash string `json:"nextUpdateOtpHash"`

	// Hash of the one-time password for this recovery/checkpoint/revoke operation.
	NextRecoveryOTPHash string `json:"nextRecoveryOtpHash"`
}

// RegisterSteps registers did exchange steps
func (d *Steps) RegisterSteps(s *godog.Suite) {
	s.Step(`^client sends request to sidetree "([^"]*)" for create DID document "([^"]*)"`, d.createDIDDocumentFromFile)
	s.Step(`^check success response contains "([^"]*)"$`, d.checkSuccessResp)
	s.Step(`^"([^"]*)" creates public DID for did method "([^"]*)"`, d.createDIDDocument)
	s.Step(`^"([^"]*)" agent successfully resolves DID document$`, d.resolveDID)
}
