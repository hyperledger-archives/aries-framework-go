/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

// This is a test nodejs app for developers to test WASM integration.

const { Aries } = require('./dist/node/aries.js')

// TODO add a 'ready' signal from the wasm to let users know when it's loaded

setTimeout(() => {
    new Aries({})._test._echo("test").then(
        response => console.log(response),
        err => console.error(err)
    )
}, 1000)

// TODO add a 'shutdown' signal to the wasm so that nodejs apps don't hang

