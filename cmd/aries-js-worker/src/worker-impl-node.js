/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

const { workerData, parentPort } = require("worker_threads")
const fs = require("fs")

// We expect two things in workerData:
// - wasmJS: absolute path to the Go webassembly wrapper JS file
// - wasm: absolute path to the wasm blob file

require(workerData.wasmJS)

const go = new Go();
go.env = Object.assign({ TMPDIR: require("os").tmpdir() }, process.env);
go.exit = process.exit;
WebAssembly.instantiate(fs.readFileSync(workerData.wasmPath), go.importObject).then((result) => {
    return go.run(result.instance);
}).catch((err) => {
    console.error(err);
    process.exit(1);
});

handleResult = function(r) {
    parentPort.postMessage(JSON.parse(r))
}

parentPort.on("message", m => {
    // handleMsg is not defined here but is instead defined by the WASM blob during initialization
    handleMsg(JSON.stringify(m))
})