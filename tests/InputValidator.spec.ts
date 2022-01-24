import InputValidator from '../lib/InputValidator';
import OperationKeyType from '../lib/enums/OperationKeyType';

describe('IonKey', async () => {
  describe('validateEs256kOperationKey', () => {
    it('should throw if given private key does not have d', () => {
      const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
      try {
        InputValidator.validateEs256kOperationKey(publicKey, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });

    it('should throw if given key does not have crv', () => {
      const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const publicKeyWithoutCrv = {
        ...publicKey,
        crv: undefined
      };
      try {
        InputValidator.validateEs256kOperationKey(publicKeyWithoutCrv, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kMissingOrInvalidCrv: SECP256K1 JWK 'crv' property must be 'secp256k1' but got 'undefined.'`);
      }
    });

    it('should throw if given key does not have kty', () => {
      const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const publicKeyWithoutKty = {
        ...publicKey,
        kty: undefined
      };
      try {
        InputValidator.validateEs256kOperationKey(publicKeyWithoutKty, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kMissingOrInvalidKty: SECP256K1 JWK 'kty' property must be 'EC' but got 'undefined.'`);
      }
    });

    it('should throw if given key has extra properties', () => {
      const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const publicKeyWithExtraProperty = {
        ...publicKey,
        extra: true
      };
      try {
        InputValidator.validateEs256kOperationKey(publicKeyWithExtraProperty, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`PublicKeyJwkEs256kHasUnexpectedProperty: SECP256K1 JWK key has unexpected property 'extra'.`);
      }
    });

    it('should throw if given key x value is not the correct length', () => {
      const publicKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const publicKeyWithInvalidX = {
        ...publicKey,
        x: 'abc'
      };
      try {
        InputValidator.validateEs256kOperationKey(publicKeyWithInvalidX, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfX: SECP256K1 JWK 'x' property must be 43 bytes.`);
      }
    });

    it('should throw if given private key d value is not the correct length', () => {
      const privateKey = require('./vectors/inputs/jwkEs256k1Private.json');
      const privateKeyClone = Object.assign({}, privateKey); // Make a copy so this test does not affect other tests.
      privateKeyClone.d = 'abc';
      try {
        InputValidator.validateEs256kOperationKey(privateKeyClone, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });
  });

  describe('validateEd25519OperationKey', () => {
    it('should throw if given private key does not have d', () => {
      const publicKey = require('./vectors/inputs/jwkEd255191Public.json');
      try {
        InputValidator.validateEd25519OperationKey(publicKey, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEd25519HasIncorrectLengthOfD: Ed25519 JWK 'd' property must be 43 bytes.`);
      }
    });

    it('should throw if given key does not have crv', () => {
      const publicKey = require('./vectors/inputs/jwkEd255191Public.json');
      const publicKeyWithoutCrv = {
        ...publicKey,
        crv: undefined
      };
      try {
        InputValidator.validateEd25519OperationKey(publicKeyWithoutCrv, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEd25519MissingOrInvalidCrv: Ed25519 JWK 'crv' property must be 'Ed25519' but got 'undefined.'`);
      }
    });

    it('should throw if given key does not have kty', () => {
      const publicKey = require('./vectors/inputs/jwkEd255191Public.json');
      const publicKeyWithoutKty = {
        ...publicKey,
        kty: undefined
      };
      try {
        InputValidator.validateEd25519OperationKey(publicKeyWithoutKty, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEd25519MissingOrInvalidKty: Ed25519 JWK 'kty' property must be 'OKP' but got 'undefined.'`);
      }
    });

    it('should throw if given key has extra properties', () => {
      const publicKey = require('./vectors/inputs/jwkEd255191Public.json');
      const publicKeyWithExtraProperty = {
        ...publicKey,
        extra: true
      };
      try {
        InputValidator.validateEd25519OperationKey(publicKeyWithExtraProperty, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`PublicKeyJwkEd25519HasUnexpectedProperty: Ed25519 JWK key has unexpected property 'extra'.`);
      }
    });

    it('should throw if given key x value is not the correct length', () => {
      const publicKey = require('./vectors/inputs/jwkEd255191Public.json');
      const publicKeyWithInvalidX = {
        ...publicKey,
        x: 'abc'
      };
      try {
        InputValidator.validateEd25519OperationKey(publicKeyWithInvalidX, OperationKeyType.Public);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEd25519HasIncorrectLengthOfX: Ed25519 JWK 'x' property must be 43 bytes.`);
      }
    });

    it('should throw if given private key d value is not the correct length', () => {
      const privateKey = require('./vectors/inputs/jwkEd255191Private.json');
      const privateKeyClone = Object.assign({}, privateKey); // Make a copy so this test does not affect other tests.
      privateKeyClone.d = 'abc';
      try {
        InputValidator.validateEd25519OperationKey(privateKeyClone, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEd25519HasIncorrectLengthOfD: Ed25519 JWK 'd' property must be 43 bytes.`);
      }
    });
  });
});
