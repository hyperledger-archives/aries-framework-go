/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

require("./wasm_exec.js")
const { parentPort } = require('worker_threads')

const go = new Go();
go.env = Object.assign({ TMPDIR: require("os").tmpdir() }, process.env);
go.exit = process.exit;
WebAssembly.instantiate(fs.readFileSync("./aries-js-worker.wasm"), go.importObject).then((result) => {
    return go.run(result.instance);
}).catch((err) => {
    console.error(err);
    process.exit(1);
});

handleResult = function(r) {
    parentPort.postMessage(JSON.parse(r))
}

parentPort.on("message", m => {
    handleMsg(JSON.stringify(m))
})