# drand verify

[![drand-verify on crates.io](https://img.shields.io/crates/v/drand-verify.svg)](https://crates.io/crates/drand-verify)
[![Docs](https://docs.rs/drand-verify/badge.svg)](https://docs.rs/drand-verify)

A [drand](https://drand.love/) verification library in Rust.
This can be used by other crates or be compiled to a Wasm blob (< 500 kilobytes) with JavaScript bindings.

## Feature overview

- Supports classic 30s mainnet/testnet ✅
- Based on well-maintained [pairing] BLS12-381 implementation ✅
- Supports [unchained mode] ✅
- G1/G2 swap ✅
- API does not expose types of the BLS implementation ✅
- Supports [bls-unchained-g1-rfc9380](https://github.com/drand/drand/pull/1249) ✅

Next up:

- Add alternative BLS12-381 implementation (especially [blst](https://github.com/supranational/blst))

The following things are intentionally unsupported:

- Network requests: we do no networking here. Our callers know much better how to do networking in their environment.
- JSON parsing: we do no decoding here. Our callers know much better how to do JSON (or protobuf) decoding in their environment.

[pairing]: https://crates.io/crates/pairing
[unchained mode]: https://drand.love/blog/2022/02/21/multi-frequency-support-and-timelock-encryption-capabilities/

## Development

Compile with

```
$ cargo test
$ cargo build --examples
```

## Run example

Verifies a random beacon (round, previous_signature, signature) against the League of Entropy
public key and calculates the corresponding randomness value.

```
$ cargo run --example drand_verify 1337 80d95247ddf1bb3acf5738497a5f10406be283144603f63d714bb1a44ff6b93285ae2697fffeb50c68862bd9fbecd4b204b1798d2686b4ac5d573615031d9d67e6168bde9a7adf1161430a498ca701a25c216aee3e38ffd5290369034fa050a2 945b08dcb30e24da281ccf14a646f0630ceec515af5c5895e18cc1b19edd65d156b71c776a369af3487f1bc6af1062500b059e01095cc0eedce91713977d7735cac675554edfa0d0481bb991ed93d333d08286192c05bf6b65d20f23a37fc7bb
Verification succeeded
Randomness: 2660664f8d4bc401194d80d81da20a1e79480f65b8e2d205aecbd143b5bfb0d3
```

## Build for JS

In order to keep the JS/Wasm interface simple, there is a wrapper in the module `verify_js.rs` which takes
inputs in hex format and uses u32 round numbers. JS/Wasm bindings are created using wasm-bindgen.

**For Node.js**

This creates a CommonJS module that is loaded synchonously.

The example uses [the League of Entropy public key](https://api3.drand.sh/info)
and [round 72785](https://api3.drand.sh/public/72785).

```
$ wasm-pack build --target nodejs -- --features js
$ node
> const { verify_beacon } = require('./pkg/drand_verify');

// all good
> verify_beacon("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31", 72785, "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747", "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42")
true

// wrong round
> verify_beacon("868f005eb8e6e4ca0a47c8a77ceaa5309a47978a7c71bc5cce96366b5d7a569937c529eeda66c7293784a9402801af31", 42, "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747", "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42")
false

// invalid pubkey length
> verify_beacon("868f", 72785, "a609e19a03c2fcc559e8dae14900aaefe517cb55c840f6e69bc8e4f66c8d18e8a609685d9917efbfb0c37f058c2de88f13d297c7e19e0ab24813079efe57a182554ff054c7638153f9b26a60e7111f71a0ff63d9571704905d3ca6df0b031747", "82f5d3d2de4db19d40a6980e8aa37842a0e55d1df06bd68bddc8d60002e8e959eb9cfa368b3c1b77d18f02a54fe047b80f0989315f83b12a74fd8679c4f12aae86eaf6ab5690b34f1fddd50ee3cc6f6cdf59e95526d5a5d82aaa84fa6f181e42")
Thrown: 'Invalid input length for point (must be in compressed format): Expected 48, actual: 2'

// unchained mode uses empty argument
> verify_beacon("8200fc249deb0148eb918d6e213980c5d01acd7fc251900d9260136da3b54836ce125172399ddc69c4e3e11429b62c11", 223344, "", "94f6b85df7cce7237e8e7df66d794ddad092de5d8bb6a791b97e905aa89852e506ac36a792eba7021e22eebf34891f8914bf9a8dd9233ea0a4c5ca00ef8404999f899073dd2eade61fe54077fee8168f83dcb61a758b6883b38904054e64a433")
true
```

**For browsers and other JS environments**

You need to change the target in order to get a suiteable package. E.g.

```
$ wasm-pack build --target web -- --features js
$ ls ./pkg
```

for browsers. Please refer to the wasm-bindgen handbook [to learn more about targets](https://rustwasm.github.io/docs/wasm-bindgen/reference/deployment.html).

## License

Apache 2.0, see [LICENSE](./LICENSE) and [NOTICE](./NOTICE)
