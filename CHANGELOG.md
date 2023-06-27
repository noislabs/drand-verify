# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Add `G2PubkeyRfc` to support [bls-unchained-g1-rfc9380](https://github.com/drand/drand/pull/1249) networks. ([#22])

[#22]: https://github.com/noislabs/drand-verify/pull/22

### Changed

- Remove free function `verify`. Use `Pubkey::verify` instead. ([#20])

[#20]: https://github.com/noislabs/drand-verify/issues/20

## [0.5.0] - 2023-03-03

### Changed

- Refactor codebase to support G1/G2 swap ([#19]).

[#19]: https://github.com/noislabs/drand-verify/pull/19

## [0.4.0]

### Added

- Add tests for [unchained mode](https://drand.love/blog/2022/02/21/multi-frequency-support-and-timelock-encryption-capabilities/).

### Changed

- Migrate from paired to pairing.
  This increases the code size but reduces the verification cost.

[unreleased]: https://github.com/noislabs/drand-verify/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/noislabs/drand-verify/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/noislabs/drand-verify/compare/v0.3.0...v0.4.0
