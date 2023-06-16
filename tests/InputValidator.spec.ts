import InputValidator from '../lib/InputValidator.js';
import OperationKeyType from '../lib/enums/OperationKeyType.js';

import privateKey from './vectors/inputs/jwkEs256k1Private.json' assert { type: 'json' };
import publicKey from './vectors/inputs/jwkEs256k1Public.json' assert { type: 'json' };

describe('IonKey', async () => {
  describe('validateEs256kOperationKey', () => {
    it('should throw if given private key does not have d', () => {
      try {
        InputValidator.validateEs256kOperationKey(publicKey, OperationKeyType.Private);
        fail();
      } catch (e: any) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });

    it('should throw if given private key d value is not the correct length', () => {
      const privateKeyClone = Object.assign({}, privateKey); // Make a copy so this test does not affect other tests.
      privateKeyClone.d = 'abc';
      try {
        InputValidator.validateEs256kOperationKey(privateKeyClone, OperationKeyType.Private);
        fail();
      } catch (e: any) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });
  });
});
