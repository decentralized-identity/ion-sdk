import IonDocumentModel from '../lib/models/IonDocumentModel.js';
import IonRequest from '../lib/IonRequest.js';
import LocalSigner from '../lib/LocalSigner.js';
import OperationType from '../lib/enums/OperationType.js';

import jwkEs256k1Private from './vectors/inputs/jwkEs256k1Private.json' assert { type: 'json' };
import jwkEs256k1Public from './vectors/inputs/jwkEs256k1Public.json' assert { type: 'json' };
import jwkEs256k2Public from './vectors/inputs/jwkEs256k2Public.json' assert { type: 'json' };
import jwkEs256k3Public from './vectors/inputs/jwkEs256k3Public.json' assert { type: 'json' };
import publicKeyModel1 from './vectors/inputs/publicKeyModel1.json' assert { type: 'json' };
import service1 from './vectors/inputs/service1.json' assert { type: 'json' };

describe('IonRequest', () => {
  describe('createCreateRequest', () => {
    it('should generate a create request with desired arguments', async () => {
      const recoveryKey = jwkEs256k1Public;
      const updateKey = jwkEs256k2Public;
      const publicKey = publicKeyModel1;
      const publicKeys = [publicKey as any];

      const service = service1;
      const services = [service];

      const document : IonDocumentModel = {
        publicKeys,
        services
      };
      const input = { recoveryKey, updateKey, document };
      const result = await IonRequest.createCreateRequest(input);
      expect(result.type).toEqual(OperationType.Create);
      expect(result.delta.updateCommitment).toEqual('EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA');
      expect(result.delta.patches.length).toEqual(1);
      expect(result.suffixData.recoveryCommitment).toEqual('EiBfOZdMtU6OBw8Pk879QtZ-2J-9FbbjSZyoaA_bqD4zhA');
      expect(result.suffixData.deltaHash).toEqual('EiCfDWRnYlcD9EGA3d_5Z1AHu-iYqMbJ9nfiqdz5S8VDbg');
    });
  });

  describe('createUpdateRequest', () => {
    it('should generate an update request with the given arguments', async () => {
      const publicKey = publicKeyModel1;
      const publicKeys = [publicKey as any];

      const service = service1;
      const services = [service];
      const input = {
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        updatePublicKey: jwkEs256k1Public,
        nextUpdatePublicKey: jwkEs256k2Public,
        signer: LocalSigner.create(jwkEs256k1Private),
        servicesToAdd: services,
        idsOfServicesToRemove: ['someId1'],
        publicKeysToAdd: publicKeys,
        idsOfPublicKeysToRemove: ['someId2']
      };

      const result = await IonRequest.createUpdateRequest(input);
      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.type).toEqual(OperationType.Update);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJ1cGRhdGVLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQXZsbVVRYy1jaDg0Slp5bmdQdkJzUkc3eWh4aUFSenlYOE5lNFQ4LTlyTncifQ.Q9MuoQqFlhYhuLDgx4f-0UM9QyCfZp_cXt7vnQ4ict5P4_ZWKwG4OXxxqFvdzE-e3ZkEbvfR0YxEIpYO9MrPFw');
      expect(result.delta.updateCommitment).toEqual('EiDKIkwqO69IPG3pOlHkdb86nYt0aNxSHZu2r-bhEznjdA');
      expect(result.delta.patches.length).toEqual(4); // add/remove service and add/remove key
    });

    it('should generate an update request with the no arguments', async () => {
      const input = {
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        updatePublicKey: jwkEs256k1Public,
        nextUpdatePublicKey: jwkEs256k2Public,
        signer: LocalSigner.create(jwkEs256k1Private)
      };

      const result = await IonRequest.createUpdateRequest(input);
      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
    });
  });

  describe('createRecoverRequest', () => {
    it('should generate a recover request with given arguments', async () => {
      const publicKey = publicKeyModel1;
      const publicKeys = [publicKey as any];

      const service = service1;
      const services = [service];

      const document : IonDocumentModel = {
        publicKeys,
        services
      };
      const result = await IonRequest.createRecoverRequest({
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        recoveryPublicKey: jwkEs256k1Public,
        nextRecoveryPublicKey: jwkEs256k2Public,
        nextUpdatePublicKey: jwkEs256k3Public,
        document,
        signer: LocalSigner.create(jwkEs256k1Private)
      });

      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.type).toEqual(OperationType.Recover);
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJyZWNvdmVyeUNvbW1pdG1lbnQiOiJFaURLSWt3cU82OUlQRzNwT2xIa2RiODZuWXQwYU54U0hadTJyLWJoRXpuamRBIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn0sImRlbHRhSGFzaCI6IkVpQm9HNlFtamlTSm5ON2phaldnaV9vZDhjR3dYSm9Nc2RlWGlWWTc3NXZ2SkEifQ.58n6Fel9DmRAXxwcJMUwYaUhmj5kigKMNrGjr7eJaJcjOmjvwlKLSjiovWiYrb9yjkfMAjpgbAdU_2EDI1_lZw');
      expect(result.delta.updateCommitment).toEqual('EiBJGXo0XUiqZQy0r-fQUHKS3RRVXw5nwUpqGVXEGuTs-g');
      expect(result.delta.patches.length).toEqual(1); // replace
    });
  });

  describe('createDeactivateRequest', () => {
    it('should generate a deactivate request with the given arguments', async () => {
      const result = await IonRequest.createDeactivateRequest({
        didSuffix: 'EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg',
        recoveryPublicKey: jwkEs256k1Public,
        signer: LocalSigner.create(jwkEs256k1Private)
      });

      expect(result.didSuffix).toEqual('EiDyOQbbZAa3aiRzeCkV7LOx3SERjjH93EXoIM3UoN4oWg');
      expect(result.type).toEqual(OperationType.Deactivate);
      expect(result.revealValue).toEqual('EiAJ-97Is59is6FKAProwDo870nmwCeP8n5nRRFwPpUZVQ');
      expect(result.signedData).toEqual('eyJhbGciOiJFUzI1NksifQ.eyJkaWRTdWZmaXgiOiJFaUR5T1FiYlpBYTNhaVJ6ZUNrVjdMT3gzU0VSampIOTNFWG9JTTNVb040b1dnIiwicmVjb3ZlcnlLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJzZWNwMjU2azEiLCJ4IjoibklxbFJDeDBleUJTWGNRbnFEcFJlU3Y0enVXaHdDUldzc29jOUxfbmo2QSIsInkiOiJpRzI5Vks2bDJVNXNLQlpVU0plUHZ5RnVzWGdTbEsyZERGbFdhQ004RjdrIn19.uLgnDBmmFzST4VTmdJcmFKVicF0kQaBqEnRQLbqJydgIg_2oreihCA5sBBIUBlSXwvnA9xdK97ksJGmPQ7asPQ');
    });
  });

  describe('validateDidSuffix', () => {
    it('should throw if id is incorrect encoding', () => {
      try {
        (IonRequest as any).validateDidSuffix('123456789012345678901234567890123456789012345/');
        fail();
      } catch (e: any) {
        expect(e.message).toEqual('EncodedStringIncorrectEncoding: Given didSuffix must be base64url string.');
      }
    });

    it('should throw if id is not multihash', () => {
      try {
        (IonRequest as any).validateDidSuffix('aaaaaaaa'); // base64 but not multihash
        fail();
      } catch (e: any) {
        expect(e.message).toEqual(`MultihashStringNotAMultihash: Given didSuffix string 'aaaaaaaa' is not a multihash after decoding.`);
      }
    });

    it('should throw if id is hashed with unsupported hash code', () => {
      try {
        (IonRequest as any).validateDidSuffix('ERSIwvEfss45KstbKYbmQCEcRpAHPg'); // this is sha1 (code 17), which is not the correct hashing algorithm (code 18)
        fail();
      } catch (e: any) {
        // eslint-disable-next-line
        expect(e.message).toEqual(`MultihashUnsupportedHashAlgorithm: Given didSuffix uses unsupported multihash algorithm with code 17, should use 18 or change IonSdkConfig to desired hashing algorithm.`);
      }
    });
  });
});
