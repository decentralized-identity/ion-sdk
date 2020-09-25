import { IonDid, IonKey } from '../lib/index';
import PublicKeyPurpose from '../lib/models/PublicKeyPurpose';
import SdkConfig from '../lib/SdkConfig';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import ErrorCode from '../lib/ErrorCode';

describe('IonDid', async () => {
  afterEach(() => {
    SdkConfig.network = undefined;
  });

  describe('createLongFormDid()', async () => {
    it('should create a long-form DID successfully.', async () => {
      const recoveryPublicKey = {
        kty: 'EC', crv: 'secp256k1', x: 'dQs_8Fv0pQOT6rPKIyDeixwV8Wp7wc5WKl-kbxXuY_4', y: '7CWpMsKGICvhYw2ZtSSxQ2GDeDstLG7c9LI2b_pLQqo'
      };

      const updatePublicKey = {
        kty: 'EC', crv: 'secp256k1', x: 'Ftbfxen6Lhr5RbptB0XTY8n3KCC1BG2VbOL0RKroz2c', y: 'BG09yQDtZQv4dS-W9pwAi7fF--UbkdpkYckXzOoG3QU'
      };

      const didDocumentPublicKeys = [{
        id: 'anySigningKeyId',
        type: 'EcdsaSecp256k1VerificationKey2019',
        jwk: { kty: 'EC', crv: 'secp256k1', x: 'aGsMG0u9FX6I54peIKqYokjnQPGhLUYTOQNc3nOvE1Q', y: 'fjilqheWQYkHNE70shMRyMDrZp8EGCfE_aL3h-yJmQA' },
        purpose: [PublicKeyPurpose.Auth, PublicKeyPurpose.General]
      }];

      const serviceEndpoints = [{
        id: 'anyServiceEndpointId',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      const longFormDid = IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys, serviceEndpoints });

      // tslint:disable-next-line: max-line-length
      const expectedMethodSpecificId = 'did:ion:EiC5-1uBg-YC2DvQRbI6eihDvk7DOYaQ08OB0I3jCe9Ydg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoiYW55U2lnbmluZ0tleUlkIiwiandrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6ImFHc01HMHU5Rlg2STU0cGVJS3FZb2tqblFQR2hMVVlUT1FOYzNuT3ZFMVEiLCJ5IjoiZmppbHFoZVdRWWtITkU3MHNoTVJ5TURyWnA4RUdDZkVfYUwzaC15Sm1RQSJ9LCJwdXJwb3NlIjpbImF1dGgiLCJnZW5lcmFsIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VfZW5kcG9pbnRzIjpbeyJlbmRwb2ludCI6Imh0dHA6Ly9hbnkuZW5kcG9pbnQiLCJpZCI6ImFueVNlcnZpY2VFbmRwb2ludElkIiwidHlwZSI6ImFueVR5cGUifV19fV0sInVwZGF0ZV9jb21taXRtZW50IjoiRWlERkM2RE9Ed0JNeG5kX19oMTFSeDRObjFlOHpubFlPUjJhLVBqeUNva2NGZyJ9LCJzdWZmaXhfZGF0YSI6eyJkZWx0YV9oYXNoIjoiRWlBbExNMC1qem1DWi1FcElVZ0laQ2piWk5yMDFfVVBMbnd5MHdfT3I0Rks0dyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUJDNGhTMVVHeVNnTmYzbWFMdnNKRUpxX05aQUlKa0pndTNKMTJMeGNESE93In19';
      expect(longFormDid).toEqual(expectedMethodSpecificId);
    });

    it('should not include network segment in DID if SDK network is set to mainnet.', async () => {
      SdkConfig.network = 'mainnet';
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] });
      expect(longFormDid.indexOf('mainnet')).toBeLessThan(0);
    });

    it('should include network segment in DID if SDK network is set to a string that is not mainnet.', async () => {
      SdkConfig.network = 'testnet';
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] });

      const didSegments = longFormDid.split(':');
      expect(didSegments.length).toEqual(5);
      expect(didSegments[2]).toEqual('testnet');
    });

    it('should throw error if given operation key contains unexpected property.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      updatePublicKey.d = 'notAllowedPropertyInPublicKey'; // 'd' is only allowed in private key.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasUnexpectedProperty
      );
    });

    it('should throw error if given operation key contains incorrect crv value.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      updatePublicKey.crv = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidCrv
      );
    });

    it('should throw error if given operation key contains incorrect kty value.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      updatePublicKey.kty = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidKty
      );
    });

    it('should throw error if given operation key contains invalid x length.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      updatePublicKey.x = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfX
      );
    });

    it('should throw error if given operation key contains invalid y length.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      updatePublicKey.y = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfY
      );
    });

    it('should throw error if given DID Document JWK is an array.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [PublicKeyPurpose.General] });
      anyDidDocumentKey.jwk = ['invalid object type'];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [anyDidDocumentKey], serviceEndpoints: [] }),
        ErrorCode.IonDidDocumentPublicKeyMissingOrIncorrectType
      );
    });

    it('should throw error if given DID Document keys with the same ID.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      const [anyDidDocumentKey1] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [PublicKeyPurpose.General] });
      const [anyDidDocumentKey2] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [PublicKeyPurpose.Auth] }); // Key ID duplicate.
      const didDocumentPublicKeys = [anyDidDocumentKey1, anyDidDocumentKey2];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys, serviceEndpoints: [] }),
        ErrorCode.IonDidDocumentPublicKeyIdDuplicated
      );
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [PublicKeyPurpose.General] });
      anyDidDocumentKey.id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [anyDidDocumentKey], serviceEndpoints: [] }),
        ErrorCode.IonKeyIdTooLong
      );
    });

    it('should throw error if given service endpoint ID exceeds maximum length.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      const serviceEndpoints = [{
        id: 'superLongServiceEndpointIdValueThatExceedsMaximumAllowedLength',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointIdTooLong
      );
    });

    it('should throw error if given service endpoint ID is not using Base64URL characters', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      const serviceEndpoints = [{
        id: 'notAllBase64UrlChars!',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointIdNotInBase64UrlCharacterSet
      );
    });

    it('should throw error if given service endpoint type exceeds maximum length.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'superLongServiceEndpointTypeValueThatExceedsMaximumAllowedLength',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointTypeTooLong
      );
    });

    it('should throw error if given service endpoint value is an array', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'anyType',
        endpoint: []
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointValueCannotBeAnArray
      );
    });

    it('should allow object as service endpoint value.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'anyType',
        endpoint: { value: 'someValue' } // `object` based endpoint value.
      }];

      const longFormDid = IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys: [], serviceEndpoints });

      expect(longFormDid).toBeDefined();
    });

    it('should throw error if resulting delta property exceeds maximum size.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const updatePublicKey = recoveryPublicKey;

      // Add many keys so that 'delta' property size exceeds max limit.
      const [anyDidDocumentKey1] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId1', purposes: [PublicKeyPurpose.General] });
      const [anyDidDocumentKey2] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId2', purposes: [PublicKeyPurpose.General] });
      const [anyDidDocumentKey3] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId3', purposes: [PublicKeyPurpose.General] });
      const [anyDidDocumentKey4] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId4', purposes: [PublicKeyPurpose.General] });
      const didDocumentPublicKeys = [anyDidDocumentKey1, anyDidDocumentKey2, anyDidDocumentKey3, anyDidDocumentKey4];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryPublicKey, updatePublicKey, didDocumentPublicKeys, serviceEndpoints: [] }),
        ErrorCode.IonDidDeltaExceedsMaximumSize
      );
    });
  });
});
