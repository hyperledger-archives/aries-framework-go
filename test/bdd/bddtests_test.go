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

	"github.com/cucumber/godog"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/test/bdd/agent"
	"github.com/hyperledger/aries-framework-go/test/bdd/dockerutil"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/connection"
	bddctx "github.com/hyperledger/aries-framework-go/test/bdd/pkg/context"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didexchange"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/didresolver"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/introduce"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/issuecredential"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/ld"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/mediator"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/messaging"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/outofband"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/presentproof"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/rfc0593"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/vdr"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/verifiable"
	"github.com/hyperledger/aries-framework-go/test/bdd/pkg/webkms"
)

const (
	SideTreeURL = "${SIDETREE_URL}"
)

//nolint:gochecknoglobals
var (
	composition  []*dockerutil.Composition
	composeFiles = []string{"./fixtures/agent-rest", "./fixtures/sidetree-mock"}
)

// Feature of the aries framework under test.
type feature interface {
	// SetContext is called before every scenario is run with a fresh new context
	SetContext(*bddctx.BDDContext)
	// invoked once to register the steps on the suite
	RegisterSteps(*godog.Suite)
}

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

//nolint:gocognit,forbidigo,gocyclo
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
				testSleep := 15
				if os.Getenv("TEST_SLEEP") != "" {
					var e error

					testSleep, e = strconv.Atoi(os.Getenv("TEST_SLEEP"))
					if e != nil {
						panic(fmt.Sprintf("Invalid value found in 'TEST_SLEEP': %s", e))
					}
				}
				fmt.Printf("*** testSleep=%d\n", testSleep)
				time.Sleep(time.Second * time.Duration(testSleep))
			}
		})
		s.AfterSuite(func() {
			err := os.Remove("docker-compose.log")
			if err != nil {
				fmt.Printf("unable to delete docker-compose.log: %v, proceeding with docker decompose..", err)
			}

			for _, c := range composition {
				if c != nil {
					if err := c.GenerateLogs(c.Dir, c.Dir+"-"+c.ProjectName+".log"); err != nil {
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

// generateUUID returns a UUID based on RFC 4122.
func generateUUID() string {
	id := dockerutil.GenerateBytesUUID()
	return fmt.Sprintf("%x-%x-%x-%x-%x", id[0:4], id[4:6], id[6:8], id[8:10], id[10:])
}

func FeatureContext(s *godog.Suite) {
	features := features()

	for _, f := range features {
		f.RegisterSteps(s)
	}

	var bddContext *bddctx.BDDContext

	s.BeforeScenario(func(interface{}) {
		bddContext = bddctx.NewBDDContext()
		// set dynamic args
		bddContext.Args[SideTreeURL] = "http://localhost:48326/sidetree/v1/"

		for _, f := range features {
			f.SetContext(bddContext)
		}
	})
	s.AfterScenario(func(_ interface{}, _ error) {
		bddContext.Destroy()
	})
}

func features() []feature {
	return []feature{
		agent.NewSDKSteps(),
		agent.NewControllerSteps(),
		didexchange.NewDIDExchangeSDKSteps(),
		didexchange.NewDIDExchangeControllerSteps(),
		introduce.NewIntroduceSDKSteps(),
		introduce.NewIntroduceControllerSteps(),
		issuecredential.NewIssueCredentialSDKSteps(),
		issuecredential.NewIssueCredentialControllerSteps(),
		didresolver.NewDIDResolverSteps(),
		messaging.NewMessagingSDKSteps(),
		messaging.NewMessagingControllerSteps(),
		mediator.NewRouteSDKSteps(),
		mediator.NewRouteRESTSteps(),
		verifiable.NewVerifiableCredentialSDKSteps(),
		outofband.NewOutOfBandSDKSteps(),
		outofband.NewOutofbandControllerSteps(),
		presentproof.NewPresentProofSDKSteps(),
		presentproof.NewPresentProofControllerSteps(),
		vdr.NewVDRControllerSteps(),
		rfc0593.NewGoSDKSteps(),
		rfc0593.NewRestSDKSteps(),
		ld.NewLDControllerSteps(),
		ld.NewSDKSteps(),
		connection.NewSDKSteps(),
		connection.NewControllerSteps(),
		webkms.NewCryptoSDKSteps(),
	}
}
