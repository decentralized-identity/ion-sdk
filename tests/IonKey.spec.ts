import { IonKey } from '../lib/index';
import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import JwkEs256k from '../lib/models/JwkEs256k';
import PublicKeyPurpose from '../lib/models/PublicKeyPurpose';

describe('IonKey', async () => {
  describe('generateEs256kOperationKeyPair()', async () => {
    it('should create a long-form DID successfully.', async () => {
      const [publicKey, privateKey] = await IonKey.generateEs256kOperationKeyPair();

      expect(Object.keys(publicKey).length).toEqual(4);
      expect(Object.keys(privateKey).length).toEqual(5);

      expect(publicKey.d).toBeUndefined();
      expect(privateKey.d).toBeDefined();
      expect(publicKey.crv).toEqual(privateKey.crv);
      expect(publicKey.kty).toEqual(privateKey.kty);
      expect(publicKey.x).toEqual(privateKey.x);
      expect(publicKey.y).toEqual(privateKey.y);
    });
  });

  describe('generateEs256kDidDocumentKeyPair()', async () => {
    it('should create a long-form DID successfully.', async () => {
      const keyId = 'anyId';
      const [didDocumentPublicKey, privateKey] = await IonKey.generateEs256kDidDocumentKeyPair(keyId, [PublicKeyPurpose.Auth]);

      expect(didDocumentPublicKey.id).toEqual(keyId);
      expect(didDocumentPublicKey.purpose).toEqual([PublicKeyPurpose.Auth]);
      expect(didDocumentPublicKey.type).toEqual('EcdsaSecp256k1VerificationKey2019');

      expect(Object.keys(didDocumentPublicKey.jwk).length).toEqual(4);
      expect(Object.keys(privateKey).length).toEqual(5);

      expect(privateKey.d).toBeDefined();

      const publicKey = didDocumentPublicKey.jwk as JwkEs256k;
      expect(publicKey.d).toBeUndefined();
      expect(publicKey.crv).toEqual(privateKey.crv);
      expect(publicKey.kty).toEqual(privateKey.kty);
      expect(publicKey.x).toEqual(privateKey.x);
      expect(publicKey.y).toEqual(privateKey.y);
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const keyId = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      await JasmineIonErrorValidator.expectSidetreeErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair(keyId, [PublicKeyPurpose.General]),
        ErrorCode.IonKeyIdTooLong
      );
    });

    it('should throw error if given DID Document key ID is not using base64URL character set. ', async () => {
      const keyId = 'nonBase64urlString!';

      await JasmineIonErrorValidator.expectSidetreeErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair(keyId, [PublicKeyPurpose.General]),
        ErrorCode.IonKeyIdNotUsingBase64UrlCharacterSet
      );
    });

    it('should throw error if given DID Document key does not have a purpose defined.', async () => {
      await JasmineIonErrorValidator.expectSidetreeErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair('anyId', []),
        ErrorCode.IonKeyPurposeNotDefined
      );
    });

    it('should throw error if given DID Document key has duplicated purposes.', async () => {
      await JasmineIonErrorValidator.expectSidetreeErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair('anyId', [PublicKeyPurpose.General, PublicKeyPurpose.General]),
        ErrorCode.IonKeyPurposeDuplicated
      );
    });
  });
});
