import ErrorCode from '../lib/ErrorCode.js';
import JasmineIonErrorValidator from './JasmineIonErrorValidator.js';
import Multihash from '../lib/Multihash.js';

describe('Multihash', async () => {
  describe('hash()', async () => {
    it('should throw error if hash algorithm given is unsupported.', async () => {
      JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => Multihash.hash(new TextEncoder().encode('anyThing'), 999),
        ErrorCode.MultihashUnsupportedHashAlgorithm
      );
    });
  });

  describe('hashAsNonMultihashBytes()', async () => {
    it('should throw error if hash algorithm given is unsupported.', async () => {
      JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => Multihash.hashAsNonMultihashBytes(new TextEncoder().encode('anyThing'), 999),
        ErrorCode.MultihashUnsupportedHashAlgorithm
      );
    });
  });
});
