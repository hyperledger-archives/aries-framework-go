module github.com/hyperledger/aries-framework-go/component/newstorage/edv

go 1.15

require (
	github.com/btcsuite/btcutil v1.0.1
	github.com/cenkalti/backoff/v4 v4.0.2
	github.com/google/tink/go v1.5.0
	github.com/google/uuid v1.1.2
	github.com/hyperledger/aries-framework-go v0.1.5
	github.com/hyperledger/aries-framework-go/component/newstorage/mem v0.0.0 // indirect
	github.com/hyperledger/aries-framework-go/component/newstorage/mock v0.0.0 // indirect
	github.com/hyperledger/aries-framework-go/test/newstorage v0.0.0
	github.com/ory/dockertest/v3 v3.6.3
	github.com/stretchr/testify v1.6.1
	github.com/trustbloc/sidetree-core-go v0.1.5

)

replace (
	github.com/hyperledger/aries-framework-go => ../../..
	github.com/hyperledger/aries-framework-go/component/newstorage/mem => ../mem
	github.com/hyperledger/aries-framework-go/component/newstorage/mock => ../mock
	github.com/hyperledger/aries-framework-go/test/newstorage => ../../../test/newstorage
)
