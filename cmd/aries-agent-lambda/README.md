# Aries Agent Lambda

Serverless powered Lambda deployment of [Aries Framework Go](https://github.com/hyperledger/aries-framework-go).
> Note: highly experimental

## 1. Requirements

- [Golang](https://golang.org/doc/install) >= 1.17
- [Node](https://nodejs.org/en/) >= v16.14
- [Yarn](https://yarnpkg.com/) >= 1.22.4
- [Docker](https://www.docker.com/) >= 20.10.12
- Make
    - [Windows](http://gnuwin32.sourceforge.net/packages/make.htm)
    - [macOS](https://brew.sh/) (via Homebrew)
    - Linux (pre-installed)

## 2. Running

1. Run `yarn install` to install all the dependencies
2. Run `yarn prepare` to install DynamoDB and build the app
3. Run `yarn start` to launch the app

The default configuration will launch and expose the route `http://localhost:3000/aries`, with all the endpoints under.
