.PHONY: build clean

build:
	env GOARCH=amd64 GOOS=linux go build -o bin/aries-agent-lambda

debug: build
	mkdir -p /tmp/dlv
	GOPATH=/tmp/dlv GOARCH=amd64 GOOS=linux go install github.com/go-delve/delve/cmd/dlv@v1.7.2
	if [ -f /tmp/dlv/bin/linux_amd64/dlv ]; then mv /tmp/dlv/bin/linux_amd64/dlv ./bin; else mv /tmp/dlv/bin/dlv ./bin; fi

clean:
	rm -rf /tmp/dlv ./bin
