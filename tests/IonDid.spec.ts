import { IonDid, IonKey, IonSdkConfig } from '../lib/index';
import DidDocumentKeyPurpose from '../lib/models/DidDocumentKeyPurpose';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';
import ErrorCode from '../lib/ErrorCode';

describe('IonDid', async () => {
  afterEach(() => {
    IonSdkConfig.network = undefined;
  });

  describe('createLongFormDid()', async () => {
    it('should create a long-form DID successfully.', async () => {
      const recoveryKey = {
        kty: 'EC', crv: 'secp256k1', x: 'dQs_8Fv0pQOT6rPKIyDeixwV8Wp7wc5WKl-kbxXuY_4', y: '7CWpMsKGICvhYw2ZtSSxQ2GDeDstLG7c9LI2b_pLQqo'
      };

      const updateKey = {
        kty: 'EC', crv: 'secp256k1', x: 'Ftbfxen6Lhr5RbptB0XTY8n3KCC1BG2VbOL0RKroz2c', y: 'BG09yQDtZQv4dS-W9pwAi7fF--UbkdpkYckXzOoG3QU'
      };

      const didDocumentKeys = [{
        id: 'anySigningKeyId',
        type: 'EcdsaSecp256k1VerificationKey2019',
        jwk: { kty: 'EC', crv: 'secp256k1', x: 'aGsMG0u9FX6I54peIKqYokjnQPGhLUYTOQNc3nOvE1Q', y: 'fjilqheWQYkHNE70shMRyMDrZp8EGCfE_aL3h-yJmQA' },
        purpose: [DidDocumentKeyPurpose.Auth, DidDocumentKeyPurpose.General]
      }];

      const serviceEndpoints = [{
        id: 'anyServiceEndpointId',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, serviceEndpoints });

      // tslint:disable-next-line: max-line-length
      const expectedMethodSpecificId = 'did:ion:EiC5-1uBg-YC2DvQRbI6eihDvk7DOYaQ08OB0I3jCe9Ydg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljX2tleXMiOlt7ImlkIjoiYW55U2lnbmluZ0tleUlkIiwiandrIjp7ImNydiI6InNlY3AyNTZrMSIsImt0eSI6IkVDIiwieCI6ImFHc01HMHU5Rlg2STU0cGVJS3FZb2tqblFQR2hMVVlUT1FOYzNuT3ZFMVEiLCJ5IjoiZmppbHFoZVdRWWtITkU3MHNoTVJ5TURyWnA4RUdDZkVfYUwzaC15Sm1RQSJ9LCJwdXJwb3NlIjpbImF1dGgiLCJnZW5lcmFsIl0sInR5cGUiOiJFY2RzYVNlY3AyNTZrMVZlcmlmaWNhdGlvbktleTIwMTkifV0sInNlcnZpY2VfZW5kcG9pbnRzIjpbeyJlbmRwb2ludCI6Imh0dHA6Ly9hbnkuZW5kcG9pbnQiLCJpZCI6ImFueVNlcnZpY2VFbmRwb2ludElkIiwidHlwZSI6ImFueVR5cGUifV19fV0sInVwZGF0ZV9jb21taXRtZW50IjoiRWlERkM2RE9Ed0JNeG5kX19oMTFSeDRObjFlOHpubFlPUjJhLVBqeUNva2NGZyJ9LCJzdWZmaXhfZGF0YSI6eyJkZWx0YV9oYXNoIjoiRWlBbExNMC1qem1DWi1FcElVZ0laQ2piWk5yMDFfVVBMbnd5MHdfT3I0Rks0dyIsInJlY292ZXJ5X2NvbW1pdG1lbnQiOiJFaUJDNGhTMVVHeVNnTmYzbWFMdnNKRUpxX05aQUlKa0pndTNKMTJMeGNESE93In19';
      expect(longFormDid).toEqual(expectedMethodSpecificId);
    });

    it('should not include network segment in DID if SDK network is set to mainnet.', async () => {
      IonSdkConfig.network = 'mainnet';
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] });
      expect(longFormDid.indexOf('mainnet')).toBeLessThan(0);
    });

    it('should include network segment in DID if SDK network is set to a string that is not mainnet.', async () => {
      IonSdkConfig.network = 'testnet';
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] });

      const didSegments = longFormDid.split(':');
      expect(didSegments.length).toEqual(5);
      expect(didSegments[2]).toEqual('testnet');
    });

    it('should throw error if given operation key contains unexpected property.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.d = 'notAllowedPropertyInPublicKey'; // 'd' is only allowed in private key.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasUnexpectedProperty
      );
    });

    it('should throw error if given operation key contains incorrect crv value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.crv = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidCrv
      );
    });

    it('should throw error if given operation key contains incorrect kty value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.kty = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidKty
      );
    });

    it('should throw error if given operation key contains invalid x length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.x = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfX
      );
    });

    it('should throw error if given operation key contains invalid y length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.y = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfY
      );
    });

    it('should throw error if given DID Document JWK is an array.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General] });
      anyDidDocumentKey.jwk = ['invalid object type'];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [anyDidDocumentKey], serviceEndpoints: [] }),
        ErrorCode.IonDidDocumentPublicKeyMissingOrIncorrectType
      );
    });

    it('should throw error if given DID Document keys with the same ID.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const [anyDidDocumentKey1] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General] });
      const [anyDidDocumentKey2] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.Auth] }); // Key ID duplicate.
      const didDocumentKeys = [anyDidDocumentKey1, anyDidDocumentKey2];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, serviceEndpoints: [] }),
        ErrorCode.IonDidDocumentPublicKeyIdDuplicated
      );
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General] });
      anyDidDocumentKey.id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [anyDidDocumentKey], serviceEndpoints: [] }),
        ErrorCode.IonKeyIdTooLong
      );
    });

    it('should throw error if given service endpoint ID exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'superLongServiceEndpointIdValueThatExceedsMaximumAllowedLength',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointIdTooLong
      );
    });

    it('should throw error if given service endpoint ID is not using Base64URL characters', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'notAllBase64UrlChars!',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointIdNotInBase64UrlCharacterSet
      );
    });

    it('should throw error if given service endpoint type exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'superLongServiceEndpointTypeValueThatExceedsMaximumAllowedLength',
        endpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointTypeTooLong
      );
    });

    it('should throw error if given service endpoint value is an array', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'anyType',
        endpoint: []
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointValueCannotBeAnArray
      );
    });

    it('should allow object as service endpoint value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'anyType',
        endpoint: { value: 'someValue' } // `object` based endpoint value.
      }];

      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints });

      expect(longFormDid).toBeDefined();
    });

    it('should throw error if given service endpoint string is not a URL.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const serviceEndpoints = [{
        id: 'anyId',
        type: 'anyType',
        endpoint: 'notValidUrl'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], serviceEndpoints }),
        ErrorCode.IonDidServiceEndpointStringNotValidUrl
      );
    });

    it('should throw error if resulting delta property exceeds maximum size.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      // Add many keys so that 'delta' property size exceeds max limit.
      const [anyDidDocumentKey1] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId1', purposes: [DidDocumentKeyPurpose.General] });
      const [anyDidDocumentKey2] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId2', purposes: [DidDocumentKeyPurpose.General] });
      const [anyDidDocumentKey3] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId3', purposes: [DidDocumentKeyPurpose.General] });
      const [anyDidDocumentKey4] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId4', purposes: [DidDocumentKeyPurpose.General] });
      const didDocumentKeys = [anyDidDocumentKey1, anyDidDocumentKey2, anyDidDocumentKey3, anyDidDocumentKey4];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, serviceEndpoints: [] }),
        ErrorCode.IonDidDeltaExceedsMaximumSize
      );
    });
  });
});
