import { IonKey, IonPublicKeyPurpose, JwkEd25519 } from '../lib/index.js';
import ErrorCode from '../lib/ErrorCode.js';
import JasmineIonErrorValidator from './JasmineIonErrorValidator.js';
import JwkEs256k from '../lib/models/JwkEs256k.js';

// NOTE: @noble/secp256k1 requires globalThis.crypto polyfill for node.js <=18: https://github.com/paulmillr/noble-secp256k1/blob/main/README.md#usage
// Remove when we move off of node.js v18 to v20, earliest possible time would be Oct 2023: https://github.com/nodejs/release#release-schedule
if (parseInt(process.versions.node) <= 18) {
  import('node:crypto').then(({ webcrypto }) => {
    // @ts-ignore
    if (!globalThis.crypto) { globalThis.crypto = webcrypto; }
    // Continue with your code that uses `crypto`
  });
}


describe('IonKey', async () => {
  describe('generateEs256kOperationKeyPair()', async () => {
    it('should create a key pair successfully.', async () => {
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
    it('should create a key pair successfully.', async () => {
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

  describe('isJwkEs256k()', async () => {
    it('should return true for a JwkEs256K key', async () => {
      const [publicKey, privateKey] = await IonKey.generateEs256kOperationKeyPair();
      expect(IonKey.isJwkEs256k(publicKey)).toBeTruthy();
      expect(IonKey.isJwkEs256k(privateKey)).toBeTruthy();
    });

    it('should return false for a JwkEd25519 key', async () => {
      const [publicKey, privateKey] = await IonKey.generateEd25519OperationKeyPair();
      expect(IonKey.isJwkEs256k(publicKey)).toBeFalsy();
      expect(IonKey.isJwkEs256k(privateKey)).toBeFalsy();
    });
  });

  describe('generateEd25519OperationKeyPair()', async () => {
    it('should create a key pair successfully.', async () => {
      const [publicKey, privateKey] = await IonKey.generateEd25519OperationKeyPair();

      expect(Object.keys(publicKey).length).toEqual(3);
      expect(Object.keys(privateKey).length).toEqual(4);

      expect(publicKey.d).toBeUndefined();
      expect(privateKey.d).toBeDefined();
      expect(publicKey.crv).toEqual(privateKey.crv);
      expect(publicKey.kty).toEqual(privateKey.kty);
      expect(publicKey.x).toEqual(privateKey.x);
    });
  });

  describe('generateEd25519DidDocumentKeyPair()', async () => {
    it('should create a key pair successfully.', async () => {
      const keyId = 'anyId';
      const [didDocumentPublicKey, privateKey] = await IonKey.generateEd25519DidDocumentKeyPair({ id: keyId, purposes: [IonPublicKeyPurpose.Authentication] });

      expect(didDocumentPublicKey.id).toEqual(keyId);
      expect(didDocumentPublicKey.purposes).toEqual([IonPublicKeyPurpose.Authentication]);
      expect(didDocumentPublicKey.type).toEqual('JsonWebKey2020');

      expect(Object.keys(didDocumentPublicKey.publicKeyJwk).length).toEqual(3);
      expect(Object.keys(privateKey).length).toEqual(4);

      expect(privateKey.d).toBeDefined();

      const publicKey = didDocumentPublicKey.publicKeyJwk as JwkEd25519;
      expect(publicKey.d).toBeUndefined();
      expect(publicKey.crv).toEqual(privateKey.crv);
      expect(publicKey.kty).toEqual(privateKey.kty);
      expect(publicKey.x).toEqual(privateKey.x);
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEd25519DidDocumentKeyPair({ id, purposes: [IonPublicKeyPurpose.Authentication] }),
        ErrorCode.IdTooLong
      );
    });

    it('should throw error if given DID Document key ID is not using base64URL character set. ', async () => {
      const id = 'nonBase64urlString!';

      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEd25519DidDocumentKeyPair({ id, purposes: [IonPublicKeyPurpose.Authentication] }),
        ErrorCode.IdNotUsingBase64UrlCharacterSet
      );
    });

    it('should allow DID Document key to not have a purpose defined.', async () => {
      const [publicKeyModel1] = await IonKey.generateEd25519DidDocumentKeyPair({ id: 'id1', purposes: [] });
      expect(publicKeyModel1.id).toEqual('id1');
      expect(publicKeyModel1.purposes).toBeUndefined();

      const [publicKeyModel2] = await IonKey.generateEd25519DidDocumentKeyPair({ id: 'id2' });
      expect(publicKeyModel2.id).toEqual('id2');
      expect(publicKeyModel2.purposes).toBeUndefined();
    });

    it('should throw error if given DID Document key has duplicated purposes.', async () => {
      await JasmineIonErrorValidator.expectIonErrorToBeThrownAsync(
        async () => IonKey.generateEd25519DidDocumentKeyPair({ id: 'anyId', purposes: [IonPublicKeyPurpose.Authentication, IonPublicKeyPurpose.Authentication] }),
        ErrorCode.PublicKeyPurposeDuplicated
      );
    });
  });

  describe('isJwkEd25519()', async () => {
    it('should return false for a JwkEs256K key', async () => {
      const [publicKey, privateKey] = await IonKey.generateEs256kOperationKeyPair();
      expect(IonKey.isJwkEd25519(publicKey)).toBeFalsy();
      expect(IonKey.isJwkEd25519(privateKey)).toBeFalsy();
    });

    it('should return false for a JwkEd25519 key', async () => {
      const [publicKey, privateKey] = await IonKey.generateEd25519OperationKeyPair();
      expect(IonKey.isJwkEd25519(publicKey)).toBeTruthy();
      expect(IonKey.isJwkEd25519(privateKey)).toBeTruthy();
    });
  });
});
