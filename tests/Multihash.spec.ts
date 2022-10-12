import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import Multihash from '../lib/Multihash';

describe('Multihash', async () => {
  describe('hashAsNonMultihashBytes()', async () => {
    it('should throw error if hash algorithm given is unsupported.', async () => {
      JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => Multihash.hashAsNonMultihashBytes(new TextEncoder().encode('anyThing'), 999),
        ErrorCode.MultihashUnsupportedHashAlgorithm
      );
    });
  });
});
