import DidDocumentKeyPurpose from '../lib/models/DidDocumentKeyPurpose';
import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import JwkEs256k from '../lib/models/JwkEs256k';
import { IonKey } from '../lib/index';

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
      const [didDocumentPublicKey, privateKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: keyId, purposes: [DidDocumentKeyPurpose.Auth] });

      expect(didDocumentPublicKey.id).toEqual(keyId);
      expect(didDocumentPublicKey.purpose).toEqual([DidDocumentKeyPurpose.Auth]);
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
      const id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id, purposes: [DidDocumentKeyPurpose.General] }),
        ErrorCode.IonKeyIdTooLong
      );
    });

    it('should throw error if given DID Document key ID is not using base64URL character set. ', async () => {
      const id = 'nonBase64urlString!';

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id, purposes: [DidDocumentKeyPurpose.General] }),
        ErrorCode.IonKeyIdNotUsingBase64UrlCharacterSet
      );
    });

    it('should throw error if given DID Document key does not have a purpose defined.', async () => {
      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [] }),
        ErrorCode.IonKeyPurposeNotDefined
      );
    });

    it('should throw error if given DID Document key has duplicated purposes.', async () => {
      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General, DidDocumentKeyPurpose.General] }),
        ErrorCode.IonKeyPurposeDuplicated
      );
    });
  });
});
