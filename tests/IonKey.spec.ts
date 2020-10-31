import { IonKey, IonPublicKeyPurpose } from '../lib/index';
import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import JwkEs256k from '../lib/models/JwkEs256k';

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
      const [didDocumentPublicKey, privateKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: keyId, purposes: [IonPublicKeyPurpose.Authentication] });

      expect(didDocumentPublicKey.id).toEqual(keyId);
      expect(didDocumentPublicKey.purposes).toEqual([IonPublicKeyPurpose.Authentication]);
      expect(didDocumentPublicKey.type).toEqual('EcdsaSecp256k1VerificationKey2019');

      expect(Object.keys(didDocumentPublicKey.publicKeyJwk).length).toEqual(4);
      expect(Object.keys(privateKey).length).toEqual(5);

      expect(privateKey.d).toBeDefined();

      const publicKey = didDocumentPublicKey.publicKeyJwk as JwkEs256k;
      expect(publicKey.d).toBeUndefined();
      expect(publicKey.crv).toEqual(privateKey.crv);
      expect(publicKey.kty).toEqual(privateKey.kty);
      expect(publicKey.x).toEqual(privateKey.x);
      expect(publicKey.y).toEqual(privateKey.y);
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id, purposes: [IonPublicKeyPurpose.Authentication] }),
        ErrorCode.IdTooLong
      );
    });

    it('should throw error if given DID Document key ID is not using base64URL character set. ', async () => {
      const id = 'nonBase64urlString!';

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id, purposes: [IonPublicKeyPurpose.Authentication] }),
        ErrorCode.IdNotUsingBase64UrlCharacterSet
      );
    });

    it('should allow DID Document key to not have a purpose defined.', async () => {
      const [publicKeyModel1] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'id1', purposes: [] });
      expect(publicKeyModel1.id).toEqual('id1');
      expect(publicKeyModel1.purposes).toBeUndefined();

      const [publicKeyModel2] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'id2' });
      expect(publicKeyModel2.id).toEqual('id2');
      expect(publicKeyModel2.purposes).toBeUndefined();
    });

    it('should throw error if given DID Document key has duplicated purposes.', async () => {
      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [IonPublicKeyPurpose.Authentication, IonPublicKeyPurpose.Authentication] }),
        ErrorCode.PublicKeyPurposeDuplicated
      );
    });
  });
});
