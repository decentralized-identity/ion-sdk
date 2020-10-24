import * as jwkEs256k1Public from './vectors/inputs/jwkEs256k1Public.json';
import * as jwkEs256k2Public from './vectors/inputs/jwkEs256k2Public.json';
import * as publicKeyModel1 from './vectors/inputs/publicKeyModel1.json';
import * as service1 from './vectors/inputs/service1.json';
import { DidDocumentKeyPurpose, IonDid, IonKey, IonSdkConfig } from '../lib/index';
import ErrorCode from '../lib/ErrorCode';
import JasmineIonErrorValidator from './JasmineIonErrorValidator';

describe('IonDid', async () => {
  afterEach(() => {
    IonSdkConfig.network = undefined;
  });

  describe('createLongFormDid()', async () => {
    it('vector test - should create a long-form DID correctly.', async () => {
      const recoveryKey = jwkEs256k1Public;
      const updateKey = jwkEs256k2Public;
      const didDocumentKeys = [publicKeyModel1 as any];
      const services = [service1];

      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, services });

      const expectedMethodSpecificId = 'did:ion:EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg:eyJkZWx0YSI6eyJwYXRjaGVzIjpbeyJhY3Rpb24iOiJyZXBsYWNlIiwiZG9jdW1lbnQiOnsicHVibGljS2V5cyI6W3siaWQiOiJwdWJsaWNLZXlNb2RlbDFJZCIsInB1YmxpY0tleUp3ayI6eyJjcnYiOiJzZWNwMjU2azEiLCJrdHkiOiJFQyIsIngiOiJ0WFNLQl9ydWJYUzdzQ2pYcXVwVkpFelRjVzNNc2ptRXZxMVlwWG45NlpnIiwieSI6ImRPaWNYcWJqRnhvR0otSzAtR0oxa0hZSnFpY19EX09NdVV3a1E3T2w2bmsifSwicHVycG9zZXMiOlsiYXV0aGVudGljYXRpb24iLCJrZXlBZ3JlZW1lbnQiXSwidHlwZSI6IkVjZHNhU2VjcDI1NmsxVmVyaWZpY2F0aW9uS2V5MjAxOSJ9XSwic2VydmljZXMiOlt7ImlkIjoic2VydmljZTFJZCIsInNlcnZpY2VFbmRwb2ludCI6Imh0dHA6Ly93d3cuc2VydmljZTEuY29tIiwidHlwZSI6InNlcnZpY2UxVHlwZSJ9XX19XSwidXBkYXRlQ29tbWl0bWVudCI6IkVpREtJa3dxTzY5SVBHM3BPbEhrZGI4Nm5ZdDBhTnhTSFp1MnItYmhFem5qZEEifSwic3VmZml4RGF0YSI6eyJkZWx0YUhhc2giOiJFaUNmRFdSbllsY0Q5RUdBM2RfNVoxQUh1LWlZcU1iSjluZmlxZHo1UzhWRGJnIiwicmVjb3ZlcnlDb21taXRtZW50IjoiRWlCZk9aZE10VTZPQnc4UGs4NzlRdFotMkotOUZiYmpTWnlvYUFfYnFENHpoQSJ9fQ';
      expect(longFormDid).toEqual(expectedMethodSpecificId);
    });

    it('should not include network segment in DID if SDK network is set to mainnet.', async () => {
      IonSdkConfig.network = 'mainnet';
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] });
      expect(longFormDid.indexOf('mainnet')).toBeLessThan(0);
    });

    it('should include network segment in DID if SDK network is set to a string that is not mainnet.', async () => {
      IonSdkConfig.network = 'testnet';
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] });

      const didSegments = longFormDid.split(':');
      expect(didSegments.length).toEqual(5);
      expect(didSegments[2]).toEqual('testnet');
    });

    it('should throw error if given operation key contains unexpected property.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.d = 'notAllowedPropertyInPublicKey'; // 'd' is only allowed in private key.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] }),
        ErrorCode.IonDidEs256kJwkHasUnexpectedProperty
      );
    });

    it('should throw error if given operation key contains incorrect crv value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.crv = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidCrv
      );
    });

    it('should throw error if given operation key contains incorrect kty value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.kty = 'wrongValue';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] }),
        ErrorCode.IonDidEs256kJwkMissingOrInvalidKty
      );
    });

    it('should throw error if given operation key contains invalid x length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.x = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfX
      );
    });

    it('should throw error if given operation key contains invalid y length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      updateKey.y = 'wrongValueLength';

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services: [] }),
        ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfY
      );
    });

    it('should throw error if given DID Document JWK is an array.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General] });
      anyDidDocumentKey.publicKeyJwk = ['invalid object type'];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [anyDidDocumentKey], services: [] }),
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
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, services: [] }),
        ErrorCode.IonDidDocumentPublicKeyIdDuplicated
      );
    });

    it('should throw error if given DID Document key ID exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;
      const [anyDidDocumentKey] = await IonKey.generateEs256kDidDocumentKeyPair({ id: 'anyId', purposes: [DidDocumentKeyPurpose.General] });
      anyDidDocumentKey.id = 'superDuperLongDidDocumentKeyIdentifierThatExceedsMaximumLength'; // Overwrite with super long string.

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [anyDidDocumentKey], services: [] }),
        ErrorCode.IonKeyIdTooLong
      );
    });

    it('should throw error if given service endpoint ID exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'superDuperLongServiceIdValueThatExceedsMaximumAllowedLength',
        type: 'anyType',
        serviceEndpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services }),
        ErrorCode.IonDidServiceIdTooLong
      );
    });

    it('should throw error if given service endpoint ID is not using Base64URL characters', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'notAllBase64UrlChars!',
        type: 'anyType',
        serviceEndpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services }),
        ErrorCode.IonDidServiceIdNotInBase64UrlCharacterSet
      );
    });

    it('should throw error if given service endpoint type exceeds maximum length.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'anyId',
        type: 'superDuperLongServiceTypeValueThatExceedsMaximumAllowedLength',
        serviceEndpoint: 'http://any.endpoint'
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services }),
        ErrorCode.IonDidServiceTypeTooLong
      );
    });

    it('should throw error if given service endpoint value is an array', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'anyId',
        type: 'anyType',
        serviceEndpoint: []
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services }),
        ErrorCode.IonDidServiceEndpointValueCannotBeAnArray
      );
    });

    it('should allow object as service endpoint value.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'anyId',
        type: 'anyType',
        serviceEndpoint: { value: 'someValue' } // `object` based endpoint value.
      }];

      const longFormDid = IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services });

      expect(longFormDid).toBeDefined();
    });

    it('should throw error if given service endpoint string is not a URL.', async () => {
      const [recoveryKey] = await IonKey.generateEs256kOperationKeyPair();
      const updateKey = recoveryKey;

      const services = [{
        id: 'anyId',
        type: 'anyType',
        serviceEndpoint: 'http://' // Invalid URI.
      }];

      JasmineIonErrorValidator.expectIonErrorToBeThrown(
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys: [], services }),
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
        () => IonDid.createLongFormDid({ recoveryKey, updateKey, didDocumentKeys, services: [] }),
        ErrorCode.IonDidDeltaExceedsMaximumSize
      );
    });
  });
});
