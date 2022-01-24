import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import LocalSigner from '../lib/LocalSigner';

describe('LocalSigner', () => {
  describe('sign', () => {
    it('should throw if the key is unsupported', async () => {
      const jwkEs256k1PrivateKey = require('./vectors/inputs/jwkEs256k1Private.json');
      const signer = LocalSigner.create(jwkEs256k1PrivateKey);
      (signer as any).privateKey = {
        ...jwkEs256k1PrivateKey,
        kty: 'XXX'
      };
      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => signer.sign({ alg: 'ES256K' }, {}),
        ErrorCode.UnsupportedKeyType
      );
    });
  });
});
