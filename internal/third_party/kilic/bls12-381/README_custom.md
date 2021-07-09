This is a fork of [High Speed BLS12-381 Implementation in Go](https://github.com/kilic/bls12-381).
The original README can be found [here](https://github.com/kilic/bls12-381/blob/master/README.md).
The original LICENSE is Apache License 2.0 and can be found [here](https://github.com/kilic/bls12-381/blob/master/LICENSE).

There are two reasons why we cannot use [original BLS12-381 library](https://github.com/kilic/bls12-381)
`kilic/bls12-381` directly as go module:
- [BBS+ signature schema](https://mattrglobal.github.io/bbs-signatures-spec/) requires `blake2b` hash function
  for `hash_to_curve_g1()` while `kilic/bls12-381` uses hardcoded `SHA-256`. A PR to allow selection of hash function
  is made but not yet approved (see [here](https://github.com/kilic/bls12-381/pull/25)).
- Patched swuMapG1 to allow for big-endian variant (https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-4.1.1),
  for interop reasons.