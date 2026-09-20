<div align="center">

# node-powhash

Native Node.js addon exposing multi-algorithm proof-of-work hashing for MoneroOcean pool tooling.

<p>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-GPL--3.0--or--later-blue.svg" alt="License: GPL-3.0-or-later"></a>
  <img src="https://img.shields.io/badge/node-%E2%89%A522.9.0-brightgreen.svg" alt="Node >=22.9.0">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg" alt="Linux and macOS">
  <img src="https://img.shields.io/badge/focus-PoW%20hashing-c2410c.svg" alt="Focus: PoW hashing">
  <a href="https://github.com/MoneroOcean"><img src="https://img.shields.io/badge/MoneroOcean-ecosystem-6f42c1.svg" alt="MoneroOcean ecosystem"></a>
</p>

</div>

## Overview

`node-powhash` is a native Node.js addon that exposes fast hashing helpers for a wide range of
proof-of-work algorithms: CryptoNight variants, RandomX, KawPow, Ethash, Etchash, Cuckaroo29,
Autolykos2, Ghostrider, Argon2, AstroBWT, and KangarooTwelve.

It is meant for pool backends, miner-facing APIs, and other Node.js services that need
deterministic PoW hashing without shelling out to an external binary. It is used alongside
[node-randomx](https://github.com/MoneroOcean/node-randomx) and
[nodejs-pool](https://github.com/MoneroOcean/nodejs-pool) in the MoneroOcean stack.

## Supported algorithm families

- **CryptoNight:** `cn/0`, `cn/1`, `cn/2`, `cn/r`, `cn/half`, `cn/fast`, `cn/xao`, `cn/rto`, `cn/gpu`, `cn/rwz`, `cn/zls`, `cn/double`, `cn/ccx`, `ghostrider`
- **CryptoNight Light:** `cn-lite/0`, `cn-lite/1`
- **CryptoNight Heavy and Pico:** heavy, `xhv`, `tube`, `pico`
- **RandomX:** `rx/0`, `rx/arq`, `rx/wow`, `rx/keva`, `rx/graft`, `rx/xeq`, plus the Scala/Panther path covered in the test suite
- **Argon2:** chukwa, wrkz, chukwa2
- **AstroBWT:** DERO, DERO-HE
- **KangarooTwelve**
- **Cuckaroo29:** `c29`, `c29s`, `c29v`, `c29b`, `c29i`
- **KawPow, Ethash, Etchash, Autolykos2**
- **PearlHash V3:** bounded CPU verification for dense and MoE plain proofs

## Install

From GitHub:

```bash
npm install https://github.com/MoneroOcean/node-powhash
```

For local development:

```bash
npm install
npm test
```

> **Build notes**
> - Node.js `>=22.9.0` and npm `>=11.10.0` (see `engines` in `package.json`)
> - Linux and macOS are supported; Windows is not advertised by package metadata or CI
> - The addon compiles locally with `node-gyp`, so you need Python 3, `make`, and a working C/C++ toolchain
> - Non-ARM builds use `-march=native`, so compile on the target CPU class or inside a compatible build image
> - No prebuilt binaries are shipped in this repo

## Usage

```js
const hashing = require("node-powhash");

const input = Buffer.from("This is a test");
const cn = hashing.cryptonight(input);
const rx = hashing.randomx(input, Buffer.alloc(32, 0x01), 0);
const [ethResult, ethMixHash] = hashing.ethash(headerHash32, nonce8, height);
const [autolykosHash, autolykosBlake2b] = hashing.autolykos2_hashes(coinbaseBuffer, 535357);
```

Exact argument patterns and vector-backed examples live in [`tests/stability.js`](tests/stability.js).

## API

| Method | Returns | Notes |
| --- | --- | --- |
| `cryptonight(data, algo?, height?)` | `Buffer` | Core CryptoNight entrypoint. Height is required for height-dependent variants such as `cn/r`-style calls. |
| `cryptonight_light(data, algo?, height?)` | `Buffer` | CryptoNight Light family. |
| `cryptonight_heavy(data, algo?, height?)` | `Buffer` | Heavy, `xhv`, and `tube` variants. |
| `cryptonight_pico(data, algo?)` | `Buffer` | Pico family helper. |
| `randomx(data, seedHash, algo?)` | `Buffer` | `seedHash` must be exactly 32 bytes. |
| `setRandomxCacheSize(size)` | `void` | Sets the RandomX cache size (integer, 1–256). |
| `getRandomxCacheSize()` | `number` | Returns the current RandomX cache size. |
| `argon2(data, algo?)` | `Buffer` | Argon2 family helpers. |
| `astrobwt(data, algo?)` | `Buffer` | AstroBWT family helpers. |
| `k12(data)` | `Buffer` | KangarooTwelve helper. |
| `kawpow(headerHash32, nonce8, mixHash32)` | `Buffer` | Returns the 32-byte KAWPOW result buffer using a supplied mixhash. |
| `kawpow_light(headerHash32, nonce8, height)` | `[Buffer, Buffer]` | Returns the 32-byte KAWPOW result buffer and computed mixhash buffer from the light cache. |
| `ethash(headerHash32, nonce8, height)` | `[Buffer, Buffer]` | Returns `[result, mixHash]`. |
| `etchash(headerHash32, nonce8, height)` | `[Buffer, Buffer]` | Returns `[result, mixHash]`. |
| `autolykos2_hashes(coinbaseBuffer, height)` | `[Buffer, Buffer]` | JS helper that returns `[hash, blake2b(hash)]`. |
| `c29*`, `c29_*packed_edges`, `c29_cycle_hash` | `number` or `Buffer` | Verification and packed-edge helpers for Cuckaroo29 variants. |
| `pearl_v3(header76, proof, target32OrFalse)` | `object` | With a full-width little-endian `target32`, fully verifies a bounded PearlHash V3 plain proof. With `false`, performs only the shared public/commitment preparation. Both modes return identical versioned `solution_data`; the full result additionally includes jackpot, candidate, and proof ID fields. `proof` is a `Buffer` or canonical base64 string. |

## Testing

| Command | What it does |
| --- | --- |
| `npm test` | Runs the fast active stability suite. This is the path used in GitHub Actions. |
| `node tests/stability.js --all` | Adds the legacy-only vectors that are still shipped in the repo. |
| `npm run test:perf` | Runs the manual performance smoke tests. This is intentionally excluded from CI. |
| `npm run test:all` | Runs stability plus perf locally. |
| `node tests/perf.js --all` | Adds the legacy-only perf cases. |

The test suites require the native addon to be built first (`npm install` / `node-gyp` build), and
they run on the CPU they are built for. GitHub Actions runs the stability suite only, on Linux
(`ubuntu-24.04`, `ubuntu-latest`) and macOS (`macos-latest`), with a small Node matrix to keep
feedback fast.

## Contributors

1. [MoneroOcean](https://github.com/MoneroOcean) for the long-running maintenance branch, major multi-algo expansion, C29 support, platform refreshes, security fixes, and the current stability-focused test direction
2. [XMRig](https://github.com/xmrig/xmrig) for the hashing implementations and low-level crypto/runtime code that power much of this addon
3. [tevador](https://github.com/tevador) for the upstream RandomX work vendored into this binding and the hashing/runtime improvements that come with it
4. Alexander Blair for the original public Node binding, early architecture, and foundational test and async work
5. [Snipa22](https://github.com/Snipa22) for early async plumbing, CryptoNight Light integration, and initial test coverage improvements
6. [SChernykh](https://github.com/SChernykh) for PoW development and integration help across the MoneroOcean stack, including RandomWOW and CryptoNightR-related work
7. [Howard Chu](https://github.com/hyc) for portability and build fixes, including Argon2 symbol-clash cleanup and broader integration work
8. [malbit](https://github.com/malbit) for RandomXEQ support and follow-up fixes
9. [kevacoin](https://github.com/kevacoin) for Keva-specific algorithm support
10. `xmvdev` for RandomV-related support in the repo history
11. `tubedev2000` for `c29b` support
12. [Diego Ferri](https://github.com/thundo) for Linux AMD detection fixes
13. `EDDragonWolf` for Waltz and ReverseWaltz-era CryptoNight variant work that remains part of the project history

## MoneroOcean ecosystem

| Component | Role |
| --- | --- |
| [nodejs-pool](https://github.com/MoneroOcean/nodejs-pool) | Pool backend — stratum, share storage, payments |
| [mo-pool-ui](https://github.com/MoneroOcean/mo-pool-ui) | Static web frontend for the pool |
| [xmr-node-proxy](https://github.com/MoneroOcean/xmr-node-proxy) | Stratum proxy / share aggregator |
| [mo-miner](https://github.com/MoneroOcean/mo-miner) | MoneroOcean end-user CPU/GPU mining client (multi-algo) |
| [multi-miner](https://github.com/MoneroOcean/multi-miner) | Multi-algo miner manager |
| [node-powhash](https://github.com/MoneroOcean/node-powhash) | Native multi-algo PoW hashing addon |
| [node-randomx](https://github.com/MoneroOcean/node-randomx) | Native RandomX hashing addon |
| [node-blocktemplate](https://github.com/MoneroOcean/node-blocktemplate) | Native block-template & serialization addon |
| [grpc-json-proxy](https://github.com/MoneroOcean/grpc-json-proxy) | gRPC ↔ JSON-RPC proxy (Tari base node) |

## License

[GPL-3.0-or-later](LICENSE)
