/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

exports.signAries = function signAries(privateKey, vc, verificationMethod) {
    return new Promise((resolve, reject) => {
        signVCAsync(privateKey, vc, verificationMethod, (err, vcSigned) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(vcSigned);
        });
    });
}

exports.verifyAries = function verifyAries(publicKey, vc) {
    return new Promise((resolve, reject) => {
        verifyVCAsync(publicKey, vc, (err) => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}

exports.deriveProofAries = function deriveProofAries(publicKey, vc, revealDoc, nonce) {
    return new Promise((resolve, reject) => {
        deriveVCProofAsync(publicKey, vc, revealDoc, nonce, (err, vcWithDerivedProof) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(vcWithDerivedProof);
        });
    });
}

exports.verifyProofAries = function verifyProofAries(publicKey, vc) {
    return new Promise((resolve, reject) => {
        verifyProofVCAsync(publicKey, vc, (err) => {
            if (err) {
                reject(err);
                return;
            }

            resolve();
        });
    });
}
