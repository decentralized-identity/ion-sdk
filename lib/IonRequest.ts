import * as URI from 'uri-js';
import ErrorCode from './ErrorCode';
import ISigner from './interfaces/ISigner';
import InputValidator from './InputValidator';
import IonCreateRequestModel from './models/IonCreateRequestModel';
import IonDeactivateRequestModel from './models/IonDeactivateRequestModel';
import IonDocumentModel from './models/IonDocumentModel';
import IonError from './IonError';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonRecoverRequestModel from './models/IonRecoverRequestModel';
import IonSdkConfig from './IonSdkConfig';
import IonServiceModel from './models/IonServiceModel';
import IonUpdateRequestModel from './models/IonUpdateRequestModel';
import JsonCanonicalizer from './JsonCanonicalizer';
import Multihash from './Multihash';
import OperationKeyType from './enums/OperationKeyType';
import OperationType from './enums/OperationType';
import PatchAction from './enums/PatchAction';
import SidetreeKeyJwk from './models/SidetreeKeyJwk';

/**
 * Class containing operations related to ION requests.
 */
export default class IonRequest {
  /**
   * Creates an ION DID create request.
   * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
   */
  public static createCreateRequest (input: {
    recoveryKey: SidetreeKeyJwk;
    updateKey: SidetreeKeyJwk;
    document: IonDocumentModel;
  }): IonCreateRequestModel {
    const recoveryKey = input.recoveryKey;
    const updateKey = input.updateKey;
    const didDocumentKeys = input.document.publicKeys;
    const services = input.document.services;

    // Validate recovery and update public keys.
    InputValidator.validateOperationKey(recoveryKey, OperationKeyType.Public);
    InputValidator.validateOperationKey(updateKey, OperationKeyType.Public);

    // Validate all given DID Document keys.
    IonRequest.validateDidDocumentKeys(didDocumentKeys);

    // Validate all given service.
    IonRequest.validateServices(services);

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;

    const patches = [{
      action: PatchAction.Replace,
      document: input.document
    }];

    const delta = {
      updateCommitment: Multihash.canonicalizeThenDoubleHashThenEncode(updateKey, hashAlgorithmInMultihashCode),
      patches
    };

    IonRequest.validateDeltaSize(delta);

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const suffixData = {
      deltaHash,
      recoveryCommitment: Multihash.canonicalizeThenDoubleHashThenEncode(recoveryKey, hashAlgorithmInMultihashCode)
    };

    const operationRequest = {
      type: OperationType.Create,
      suffixData: suffixData,
      delta: delta
    };

    return operationRequest;
  }

  public static async createDeactivateRequest (input: {
    didSuffix: string,
    recoveryPublicKey: SidetreeKeyJwk,
    signer: ISigner
  }): Promise<IonDeactivateRequestModel> {
    // Validate DID suffix
    IonRequest.validateDidSuffix(input.didSuffix);

    // Validates recovery public key
    InputValidator.validateOperationKey(input.recoveryPublicKey, OperationKeyType.Public);

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;
    const revealValue = Multihash.canonicalizeThenHashThenEncode(input.recoveryPublicKey, hashAlgorithmInMultihashCode);

    const dataToBeSigned = {
      didSuffix: input.didSuffix,
      recoveryKey: input.recoveryPublicKey
    };

    const compactJws = await input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);

    return {
      type: OperationType.Deactivate,
      didSuffix: input.didSuffix,
      revealValue: revealValue,
      signedData: compactJws
    };
  }

  public static async createRecoverRequest (input: {
    didSuffix: string,
    recoveryPublicKey: SidetreeKeyJwk,
    nextRecoveryPublicKey: SidetreeKeyJwk,
    nextUpdatePublicKey: SidetreeKeyJwk,
    document: IonDocumentModel,
    signer: ISigner
  }): Promise<IonRecoverRequestModel> {
    // Validate DID suffix
    IonRequest.validateDidSuffix(input.didSuffix);

    // Validate recovery public key
    InputValidator.validateOperationKey(input.recoveryPublicKey, OperationKeyType.Public);

    // Validate next recovery public key
    InputValidator.validateOperationKey(input.nextRecoveryPublicKey, OperationKeyType.Public);

    // Validate next update public key
    InputValidator.validateOperationKey(input.nextUpdatePublicKey, OperationKeyType.Public);

    // Validate all given DID Document keys.
    IonRequest.validateDidDocumentKeys(input.document.publicKeys);

    // Validate all given service.
    IonRequest.validateServices(input.document.services);

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;
    const revealValue = Multihash.canonicalizeThenHashThenEncode(input.recoveryPublicKey, hashAlgorithmInMultihashCode);

    const patches = [{
      action: PatchAction.Replace,
      document: input.document
    }];

    const nextUpdateCommitmentHash = Multihash.canonicalizeThenDoubleHashThenEncode(input.nextUpdatePublicKey, hashAlgorithmInMultihashCode);
    const delta = {
      patches,
      updateCommitment: nextUpdateCommitmentHash
    };

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);
    const nextRecoveryCommitmentHash = Multihash.canonicalizeThenDoubleHashThenEncode(input.nextRecoveryPublicKey, hashAlgorithmInMultihashCode);

    const dataToBeSigned = {
      recoveryCommitment: nextRecoveryCommitmentHash,
      recoveryKey: input.recoveryPublicKey,
      deltaHash: deltaHash
    };

    const compactJws = await input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);

    return {
      type: OperationType.Recover,
      didSuffix: input.didSuffix,
      revealValue: revealValue,
      delta: delta,
      signedData: compactJws
    };
  }

  public static async createUpdateRequest (input: {
    didSuffix: string;
    updatePublicKey: SidetreeKeyJwk;
    nextUpdatePublicKey: SidetreeKeyJwk;
    signer: ISigner;
    servicesToAdd?: IonServiceModel[];
    idsOfServicesToRemove?: string[];
    publicKeysToAdd?: IonPublicKeyModel[];
    idsOfPublicKeysToRemove?: string[];
  }): Promise<IonUpdateRequestModel> {
    // Validate DID suffix
    IonRequest.validateDidSuffix(input.didSuffix);

    // Validate update public key
    InputValidator.validateOperationKey(input.updatePublicKey, OperationKeyType.Public);

    // Validate next update public key
    InputValidator.validateOperationKey(input.nextUpdatePublicKey, OperationKeyType.Public);

    // Validate all given service.
    IonRequest.validateServices(input.servicesToAdd);

    // Validate all given DID Document keys.
    IonRequest.validateDidDocumentKeys(input.publicKeysToAdd);

    // Validate all given service id to remove.
    if (input.idsOfServicesToRemove !== undefined) {
      for (const id of input.idsOfServicesToRemove) {
        InputValidator.validateId(id);
      }
    }

    // Validate all given public key id to remove.
    if (input.idsOfPublicKeysToRemove !== undefined) {
      for (const id of input.idsOfPublicKeysToRemove) {
        InputValidator.validateId(id);
      }
    }

    const patches = [];
    // Create patches for add services
    const servicesToAdd = input.servicesToAdd;
    if (servicesToAdd !== undefined && servicesToAdd.length > 0) {
      const patch = {
        action: PatchAction.AddServices,
        services: servicesToAdd
      };

      patches.push(patch);
    }

    // Create patches for remove services
    const idsOfServicesToRemove = input.idsOfServicesToRemove;
    if (idsOfServicesToRemove !== undefined && idsOfServicesToRemove.length > 0) {
      const patch = {
        action: PatchAction.RemoveServices,
        ids: idsOfServicesToRemove
      };

      patches.push(patch);
    }

    // Create patches for adding public keys
    const publicKeysToAdd = input.publicKeysToAdd;
    if (publicKeysToAdd !== undefined && publicKeysToAdd.length > 0) {
      const patch = {
        action: PatchAction.AddPublicKeys,
        publicKeys: publicKeysToAdd
      };

      patches.push(patch);
    }

    // Create patch for removing public keys
    const idsOfPublicKeysToRemove = input.idsOfPublicKeysToRemove;
    if (idsOfPublicKeysToRemove !== undefined && idsOfPublicKeysToRemove.length > 0) {
      const patch = {
        action: PatchAction.RemovePublicKeys,
        ids: idsOfPublicKeysToRemove
      };

      patches.push(patch);
    }

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;
    const revealValue = Multihash.canonicalizeThenHashThenEncode(input.updatePublicKey, hashAlgorithmInMultihashCode);

    const nextUpdateCommitmentHash = Multihash.canonicalizeThenDoubleHashThenEncode(input.nextUpdatePublicKey, hashAlgorithmInMultihashCode);
    const delta = {
      patches,
      updateCommitment: nextUpdateCommitmentHash
    };
    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const dataToBeSigned = {
      updateKey: input.updatePublicKey,
      deltaHash: deltaHash
    };

    const compactJws = await input.signer.sign({ alg: 'ES256K' }, dataToBeSigned);

    return {
      type: OperationType.Update,
      didSuffix: input.didSuffix,
      revealValue,
      delta,
      signedData: compactJws
    };
  }

  private static validateDidSuffix (didSuffix: string) {
    Multihash.validateEncodedHashComputedUsingSupportedHashAlgorithm(didSuffix, 'didSuffix');
  }

  private static validateDidDocumentKeys (publicKeys?: IonPublicKeyModel[]) {
    if (publicKeys === undefined) {
      return;
    }

    // Validate each public key.
    const publicKeyIdSet: Set<string> = new Set();
    for (const publicKey of publicKeys) {
      if (Array.isArray(publicKey.publicKeyJwk)) {
        throw new IonError(ErrorCode.DidDocumentPublicKeyMissingOrIncorrectType, `DID Document key 'publicKeyJwk' property is not a non-array object.`);
      }

      InputValidator.validateId(publicKey.id);

      // 'id' must be unique across all given keys.
      if (publicKeyIdSet.has(publicKey.id)) {
        throw new IonError(ErrorCode.DidDocumentPublicKeyIdDuplicated, `DID Document key with ID '${publicKey.id}' already exists.`);
      }
      publicKeyIdSet.add(publicKey.id);

      InputValidator.validatePublicKeyPurposes(publicKey.purposes);
    }
  }

  private static validateServices (services?: IonServiceModel[]) {
    if (services !== undefined && services.length !== 0) {
      const serviceIdSet: Set<string> = new Set();
      for (const service of services) {
        IonRequest.validateService(service);
        if (serviceIdSet.has(service.id)) {
          throw new IonError(ErrorCode.DidDocumentServiceIdDuplicated, 'Service id has to be unique');
        }
        serviceIdSet.add(service.id);
      }
    }
  }

  private static validateService (service: IonServiceModel) {
    InputValidator.validateId(service.id);

    const maxTypeLength = 30;
    if (service.type.length > maxTypeLength) {
      const errorMessage = `Service endpoint type length ${service.type.length} exceeds max allowed length of ${maxTypeLength}.`;
      throw new IonError(ErrorCode.ServiceTypeTooLong, errorMessage);
    }

    // Throw error if `serviceEndpoint` is an array.
    if (Array.isArray(service.serviceEndpoint)) {
      const errorMessage = 'Service endpoint value cannot be an array.';
      throw new IonError(ErrorCode.ServiceEndpointCannotBeAnArray, errorMessage);
    }

    if (typeof service.serviceEndpoint === 'string') {
      const uri = URI.parse(service.serviceEndpoint);
      if (uri.error !== undefined) {
        throw new IonError(ErrorCode.ServiceEndpointStringNotValidUri, `Service endpoint string '${service.serviceEndpoint}' is not a URI.`);
      }
    }
  }

  private static validateDeltaSize (delta: object) {
    const deltaBuffer = JsonCanonicalizer.canonicalizeAsBuffer(delta);
    if (deltaBuffer.length > IonSdkConfig.maxCanonicalizedDeltaSizeInBytes) {
      const errorMessage = `Delta of ${deltaBuffer.length} bytes exceeded limit of ${IonSdkConfig.maxCanonicalizedDeltaSizeInBytes} bytes.`;
      throw new IonError(ErrorCode.DeltaExceedsMaximumSize, errorMessage);
    }
  }
}
