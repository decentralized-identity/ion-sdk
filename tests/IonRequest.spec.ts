import { IonDocumentModel } from '../lib';
import IonRequest from '../lib/IonRequest';
import OperationType from '../lib/enums/OperationType';

describe('IonRequest', () => {
  describe('createCreateRequest', () => {
    it('should generate a create request with desired arguments', async () => {
      const recoveryKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const updateKey = require('./vectors/inputs/jwkEs256k2Public.json');
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = {
        id: 'service1',
        type: 'website',
        serviceEndpoint: 'https://www.some.web.site.com'
      };
      const services = [service];

      const document : IonDocumentModel = {
        publicKeys,
        services
      };
      const input = { recoveryKey, updateKey, document };
      const result = IonRequest.createCreateRequest(input);
      expect(result.type).toEqual(OperationType.Create);
      expect(result.delta.updateCommitment).toEqual('EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA');
      expect(result.delta.patches.length).toEqual(1);
      expect(result.suffixData.recoveryCommitment).toEqual('EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA');
      expect(result.suffixData.deltaHash).toEqual('EiAdz754IZmW-nizq4Zpr_hoX5P5r7KbVfJWfDclCxKnHg');
    });
  });

  describe('createUpdateRequest', () => {
    it('should generate an update request with the given arguments', async () => {
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = {
        id: 'service1',
        type: 'website',
        serviceEndpoint: 'https://www.some.web.site.com'
      };
      const services = [service];
      const input = {
        didSuffix: 'someString',
        updatePrivateKey: require('./vectors/inputs/jwkEs256k1Private.json'),
        nextUpdatePublicKey: require('./vectors/inputs/jwkEs256k2Public.json'),
        servicesToAdd: services,
        idsOfServicesToRemove: ['someId1'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['someId2']
      };

      const result = await IonRequest.createUpdateRequest(input);
      expect(result.didSuffix).toEqual('someString');
      expect(result.type).toEqual(OperationType.Update);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpRFUzREM3TTVERjRvRFBIYmk0ZV9lTTBmWm1aMHNhSWFabERlNV9qMWJEZncifQ.Lwd1I0mmM1_7jTPxklynXRaE0cFlUVBju0ZChZzZaNsQTqTEgX5_DNRcDCapeCYn6JpRhEhay-SYaFLwS29vWg');
      expect(result.delta.updateCommitment).toEqual('EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA');
      expect(result.delta.patches.length).toEqual(4); // add/remove service and add/remove key
    });
  });

  describe('createRecoverRequest', () => {
    it('should generate a recover request with given arguments', async () => {
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = {
        id: 'service1',
        type: 'website',
        serviceEndpoint: 'https://www.some.web.site.com'
      };
      const services = [service];

      const document : IonDocumentModel = {
        publicKeys,
        services
      };
      const result = await IonRequest.createRecoverRequest({
        didSuffix: 'someString',
        recoveryPrivateKey: require('./vectors/inputs/jwkEs256k1Private.json'),
        nextRecoveryPublicKey: require('./vectors/inputs/jwkEs256k2Public.json'),
        nextUpdatePublicKey: require('./vectors/inputs/jwkEs256k3Public.json'),
        document
      });

      expect(result.didSuffix).toEqual('someString');
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.type).toEqual(OperationType.Recover);
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaURLSWt3cU82OUlQRzNwT2xIa2RiODZuWXQwYU54U0hadTJyLWJoRXpuamRBIiwicmVjb3ZlcnlLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZJWUdXYzlaRi1CM3N5UU80bU9uOTZrajI2b21zTkFIclkxdVY5WWxRSXcifQ.WzbEhitn1pLeXEFqfupbpOqCVXA6V-VQccdEo6pH7rEZULfwuFfqns1APVwrBUNM7CX_MiaIajnZrMVXhrdS1g');
      expect(result.delta.updateCommitment).toEqual('EiBJGXo0XUiqZQy0r-fQUHKS3RRVXw5nwUpqGVXEGuTs-g');
      expect(result.delta.patches.length).toEqual(1); // replace
    });
  });

  describe('createDeactivateRequest', () => {
    it('shuold generate a deactivate request with the given arguments', async () => {
      const result = await IonRequest.createDeactivateRequest({
        didSuffix: 'someString',
        recoveryPrivateKey: require('./vectors/inputs/jwkEs256k1Private.json')
      });

      expect(result.didSuffix).toEqual('someString');
      expect(result.type).toEqual(OperationType.Deactivate);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJzb21lU3RyaW5nIiwicmVjb3ZlcnlLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn19.egHlZRc3kSUCfVe0JPIzI6FnUtGVmM-DFsyejHvcXTF0gPnKKSzvVVVWJE2wb-ctKGLnqohmyLgn31OOuDXEzQ');
    });
  });
});
