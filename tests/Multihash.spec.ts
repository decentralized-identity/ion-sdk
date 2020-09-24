import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import Multihash from '../lib/Multihash';

describe('Multihash', async () => {
  describe('hashAsNonMultihashBuffer()', async () => {
    it('should throw error if hash.', async () => {
      JasmineIonErrorValidator.expectSidetreeErrorToBeThrown(
        () => Multihash.hashAsNonMultihashBuffer(Buffer.from('anyThing'), 999),
        ErrorCode.MultihashUnsupportedHashAlgorithm
      );
    });
  });
});
