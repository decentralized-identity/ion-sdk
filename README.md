# TypeScript/JavaScript SDK for `did:ion`
- This SDK allows you to create `did:ion` operations that are ready to be submitted to an ION node.
- You can also use the SDK to create long-form ION DIDs.
- This SDK is compatible with both node.js and browser.

Code Coverage

![Statements](https://img.shields.io/badge/statements-100%25-brightgreen.svg?style=flat) ![Branches](https://img.shields.io/badge/branches-100%25-brightgreen.svg?style=flat) ![Functions](https://img.shields.io/badge/functions-100%25-brightgreen.svg?style=flat) ![Lines](https://img.shields.io/badge/lines-100%25-brightgreen.svg?style=flat)

```
npm i @decentralized-identity/ion-sdk --save
```

## Additional Setup
This package depends on the [`@noble/ed25519`](https://github.com/paulmillr/noble-ed25519#usage) and [`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1#usage) v2, thus additional steps are needed for some environments:

```ts
// node.js 18 and earlier, needs globalThis.crypto polyfill
import { webcrypto } from 'node:crypto';
// @ts-ignore
if (!globalThis.crypto) globalThis.crypto = webcrypto;

// React Native needs crypto.getRandomValues polyfill and sha256 for `@noble/secp256k1`
import 'react-native-get-random-values';
import { hmac } from '@noble/hashes/hmac';
import { sha256 } from '@noble/hashes/sha256';
secp.etc.hmacSha256Sync = (k, ...m) => hmac(sha256, k, secp.etc.concatBytes(...m));
secp.etc.hmacSha256Async = (k, ...m) => Promise.resolve(secp.etc.hmacSha256Sync(k, ...m));

// React Native needs crypto.getRandomValues polyfill and sha512 for `@noble/ed25519`
import 'react-native-get-random-values';
import { sha512 } from '@noble/hashes/sha512';
ed.etc.sha512Sync = (...m) => sha512(ed.etc.concatBytes(...m));
ed.etc.sha512Async = (...m) => Promise.resolve(ed.etc.sha512Sync(...m));
```
