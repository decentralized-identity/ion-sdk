import { IonKey } from '../lib/index';
import PublicKeyPurpose from '../lib/models/PublicKeyPurpose';
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

  describe('createLongFormDid()', async () => {
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
  });
});
