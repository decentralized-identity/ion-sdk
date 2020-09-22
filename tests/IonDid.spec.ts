import { IonDid, IonKey } from '../lib/index';
import PublicKeyPurpose from '../lib/models/PublicKeyPurpose';

describe('IonDid', async () => {
  describe('createLongFormDid()', async () => {
    it('should create a long-form DID successfully.', async () => {
      const [recoveryPublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const [updatePublicKey] = await IonKey.generateEs256kOperationKeyPair();
      const [signingPublicKey] = await IonKey.generateEs256kDidDocumentKeyPair('anySigningKeyId', [PublicKeyPurpose.Auth]);
      const serviceEndpoint = {
        id: 'anyServiceEndpointId',
        type: 'anyType',
        endpoint: 'http://any.endpoint'
      };
      const longFormDid = IonDid.createLongFormDid(recoveryPublicKey, updatePublicKey, [signingPublicKey], [serviceEndpoint]);
      const didParts = longFormDid.split(':');
      expect(didParts[0]).toEqual('did');
      expect(didParts[1]).toEqual('ion');
    });
  });
});
