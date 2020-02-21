/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/introduce"

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/messaging"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/route"
)

const (
	SideTreeURL = "${SIDETREE_URL}"
	DIDDocPath  = "${DID_DOC_PATH}"
)

var composition []*dockerutil.Composition
var composeFiles = []string{"./fixtures/agent-rest", "./fixtures/sidetree-mock"}

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	flag.Parse()

	format := "progress"
	if getCmdArg("test.v") == "true" {
		format = "pretty"
	}

	runArg := getCmdArg("test.run")
	if runArg != "" {
		tags = runArg
	}

	agentLogLevel := os.Getenv("AGENT_LOG_LEVEL")
	if agentLogLevel != "" {
		logLevel, err := log.ParseLevel(agentLogLevel)
		if err != nil {
			panic(err)
		}

		log.SetLevel(os.Getenv("AGENT_LOG_MODULE"), logLevel)
	}

	status := runBddTests(tags, format)
	if st := m.Run(); st > status {
		status = st
	}

	os.Exit(status)
}

//nolint:gocognit
func runBddTests(tags, format string) int {
	return godog.RunWithOptions("godogs", func(s *godog.Suite) {
		s.BeforeSuite(func() {
			if os.Getenv("DISABLE_COMPOSITION") != "true" {
				// Need a unique name, but docker does not allow '-' in names
				composeProjectName := strings.ReplaceAll(generateUUID(), "-", "")

				for _, v := range composeFiles {
					newComposition, err := dockerutil.NewComposition(composeProjectName, "docker-compose.yml", v)
					if err != nil {
						panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
					}
					composition = append(composition, newComposition)
				}
				fmt.Println("docker-compose up ... waiting for containers to start ...")
				testSleep := 5
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}
				fmt.Printf("*** testSleep=%d", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))
			}
		})
		s.AfterSuite(func() {
			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, c.ProjectName+".log"); err != nil {
						panic(err)
					}
					if _, err := c.Decompose(c.Dir); err != nil {
						panic(err)
					}
				}
			}
		})
		FeatureContext(s)
	}, godog.Options{
		Tags:          tags,
		Format:        format,
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})
}

func getCmdArg(argName string) string {
	cmdTags := flag.CommandLine.Lookup(argName)
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		return cmdTags.Value.String()
	}

	return ""
}

// generateUUID returns a UUID based on RFC 4122
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func FeatureContext(s *godog.Suite) {
	bddContext, err := bddctx.NewBDDContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// set dynamic args
	bddContext.Args[SideTreeURL] = "http://localhost:48326/document"
	bddContext.Args[DIDDocPath] = "fixtures/sidetree-mock/config/didDocument.json"

	// Context is shared between tests
	agent.NewSDKSteps(bddContext).RegisterSteps(s)
	agent.NewControllerSteps(bddContext).RegisterSteps(s)

	// Register did exchange tests
	didexchange.NewDIDExchangeSDKSteps(bddContext).RegisterSteps(s)
	didexchange.NewDIDExchangeControllerSteps(bddContext).RegisterSteps(s)

	// Register introduce tests
	introduce.NewIntroduceSDKSteps(bddContext).RegisterSteps(s)

	// Register did resolver tests
	didresolver.NewDIDResolverSteps(bddContext).RegisterSteps(s)

	// Register messaging tests
	messaging.NewMessagingSDKSteps(bddContext).RegisterSteps(s)
	messaging.NewMessagingControllerSteps(bddContext).RegisterSteps(s)

	// Register router tests
	route.NewRouteSDKSteps(bddContext).RegisterSteps(s)
	route.NewRouteRESTSteps(bddContext).RegisterSteps(s)
}
