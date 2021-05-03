import { IonDocumentModel } from '../lib';
import IonRequest from '../lib/IonRequest';
import OperationKeyType from '../lib/enums/OperationKeyType';
import OperationType from '../lib/enums/OperationType';

describe('IonRequest', () => {
  describe('createCreateRequest', () => {
    it('should generate a create request with desired arguments', async () => {
      const recoveryKey = require('./vectors/inputs/jwkEs256k1Public.json');
      const updateKey = require('./vectors/inputs/jwkEs256k2Public.json');
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = require('./vectors/inputs/service1.json');
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
      expect(result.suffixData.deltaHash).toEqual('EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg');
    });
  });

  describe('createUpdateRequest', () => {
    it('should generate an update request with the given arguments', async () => {
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = require('./vectors/inputs/service1.json');
      const services = [service];
      const input = {
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        updatePrivateKey: require('./vectors/inputs/jwkEs256k1Private.json'),
        nextUpdatePublicKey: require('./vectors/inputs/jwkEs256k2Public.json'),
        servicesToAdd: services,
        idsOfServicesToRemove: ['someId1'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['someId2']
      };

      const result = await IonRequest.createUpdateRequest(input);
      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.type).toEqual(OperationType.Update);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZsbVVRYy1jaDg0Slp5bmdQdkJzUkc3eWh4aUFSenlYOE5lNFQ4LTlyTncifQ.mbXK3d_KruRQB5ZviM-ow3UaIdUY3m1o1o9TdHAW23Z11upHglVr7Yfb-cvmJL6iL0qZxWiT9R5hpoIOPOkWJQ');
      expect(result.delta.updateCommitment).toEqual('EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA');
      expect(result.delta.patches.length).toEqual(4); // add/remove service and add/remove key
    });

    it('should generate an update request with the no arguments', async () => {
      const input = {
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        updatePrivateKey: require('./vectors/inputs/jwkEs256k1Private.json'),
        nextUpdatePublicKey: require('./vectors/inputs/jwkEs256k2Public.json')
      };

      const result = await IonRequest.createUpdateRequest(input);
      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
    });
  });

  describe('createRecoverRequest', () => {
    it('should generate a recover request with given arguments', async () => {
      const publicKey = require('./vectors/inputs/publicKeyModel1.json');
      const publicKeys = [publicKey];

      const service = require('./vectors/inputs/service1.json');
      const services = [service];

      const document : IonDocumentModel = {
        publicKeys,
        services
      };
      const result = await IonRequest.createRecoverRequest({
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        recoveryPrivateKey: require('./vectors/inputs/jwkEs256k1Private.json'),
        nextRecoveryPublicKey: require('./vectors/inputs/jwkEs256k2Public.json'),
        nextUpdatePublicKey: require('./vectors/inputs/jwkEs256k3Public.json'),
        document
      });

      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.type).toEqual(OperationType.Recover);
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaURLSWt3cU82OUlQRzNwT2xIa2RiODZuWXQwYU54U0hadTJyLWJoRXpuamRBIiwicmVjb3ZlcnlLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQm9HNlFtamlTSm5ON2phaldnaV9vZDhjR3dYSm9Nc2RlWGlWWTc3NXZ2SkEifQ.ZL5ThTp1rLPtcsf6rUk8DwkkkmP8f70Mor-lk2Jru5VJlMBlPOKb3saCqlCxlopD8e-sGZsyx3xi4Pf4KeY_NQ');
      expect(result.delta.updateCommitment).toEqual('EiBJGXo0XUiqZQy0r-fQUHKS3RRVXw5nwUpqGVXEGuTs-g');
      expect(result.delta.patches.length).toEqual(1); // replace
    });
  });

  describe('createDeactivateRequest', () => {
    it('shuold generate a deactivate request with the given arguments', async () => {
      const result = await IonRequest.createDeactivateRequest({
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        recoveryPrivateKey: require('./vectors/inputs/jwkEs256k1Private.json')
      });

      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.type).toEqual(OperationType.Deactivate);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsiY3J2Ijoic2VjcDI1NmsxIiwia3R5IjoiRUMiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn19.9rSNNrh5vaT0cSsHt4lElKTm7rbxNhmIGGSA238O91dxs9-OKDM_ktfK5RmhBd7qfM6wJTJcdPCOnufTj5jbRA');
    });
  });

  describe('validateEs256kOperationKey', () => {
    it('should throw if given private key does not have d', () => {
      const privKey = require('./vectors/inputs/jwkEs256k1Private.json');
      privKey.d = undefined;
      try {
        (IonRequest as any).validateEs256kOperationKey(privKey, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });

    it('should throw if given private key d value is not the correct length', () => {
      const privKey = require('./vectors/inputs/jwkEs256k1Private.json');
      privKey.d = 'abc';
      try {
        (IonRequest as any).validateEs256kOperationKey(privKey, OperationKeyType.Private);
        fail();
      } catch (e) {
        expect(e.message).toEqual(`JwkEs256kHasIncorrectLengthOfD: SECP256K1 JWK 'd' property must be 43 bytes.`);
      }
    });
  });

  describe('validateDidSuffix', () => {
    it('should throw if id is incorrect encoding', () => {
      try {
        (IonRequest as any).validateDidSuffix('123456789012345678901234567890123456789012345/');
        fail();
      } catch (e) {
        expect(e.message).toEqual('EncodedMultiHashIncorrectEncoding: Given didSuffix must be base64url string.');
      }
    });

    it('should throw if id is not multihash', () => {
      try {
        (IonRequest as any).validateDidSuffix('aaaaaaaa'); // base64 but not multihash
        fail();
      } catch (e) {
        expect(e.message).toEqual(`MultihashStringNotAMultihash: Given didSuffix string 'aaaaaaaa' is not a multihash after decoding.`);
      }
    });

    it('should throw if id is hashed with unsupported hash code', () => {
      try {
        (IonRequest as any).validateDidSuffix('ERSIwvEfss45KstbKYbmQCEcRpAHPg'); // this is sha1 (code 17), which is not the correct hashing algorithm (code 18)
        fail();
      } catch (e) {
        // eslint-disable-next-line
        expect(e.message).toEqual(`MultihashUnsupportedHashAlgorithm: Given didSuffix uses unsupported multihash algorithm with code 17, should use 18 or change IonSdkConfig to desired hashing algorithm.`);
      }
    });
  });
});
