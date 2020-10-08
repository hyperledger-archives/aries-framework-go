package bbsblssignature2020

import (
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/crypto/bls"
	sigverifier "github.com/hyperledger/aries-framework-go/pkg/doc/signature/verifier"
)

type Verifier struct {
	bls bls.Bls
}

func NewVerifier(bls bls.Bls) *Verifier {
	return &Verifier{
		bls: bls,
	}
}

// Verify will verify a signature.
func (v *Verifier) Verify(pubKeyValue *sigverifier.PublicKey, doc, signature []byte) error {
	messages := parseMessages(doc)

	return v.bls.Verify(messages, signature, pubKeyValue.Value)
}

func parseMessages(doc []byte) [][]byte {
	docStr := string(doc)

	messagesStr := strings.Split(docStr, "\n")
	messagesBytes := make([][]byte, 0, len(messagesStr))

	for i := range messagesStr {
		if messagesStr[i] != "" {
			messagesBytes = append(messagesBytes, []byte(messagesStr[i]))
		}
	}

	return messagesBytes

}
