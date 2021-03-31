import * as URI from 'uri-js';
import ErrorCode from './ErrorCode';
import InputValidator from './InputValidator';
import IonCreateRequestModel from './models/IonCreateRequestModel';
import IonDocumentModel from './models/IonDocumentModel';
import IonError from './IonError';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonSdkConfig from './IonSdkConfig';
import IonServiceModel from './models/IonServiceModel';
import JsonCanonicalizer from './JsonCanonicalizer';
import JwkEs256k from './models/JwkEs256k';
import Multihash from './Multihash';
import OperationType from './enums/OperationType';
import PatchAction from './enums/PatchAction';
const secp256k1 = require('@transmute/did-key-secp256k1');

/**
 * Class containing operations related to ION requests.
 */
export default class IonRequest {
  /**
   * Creates an ION DID create request.
   * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
   */
  public static createCreateRequest (input: {
    recoveryKey: JwkEs256k;
    updateKey: JwkEs256k;
    document: IonDocumentModel;
  }): IonCreateRequestModel {
    const recoveryKey = input.recoveryKey;
    const updateKey = input.updateKey;
    const didDocumentKeys = input.document.publicKeys;
    const services = input.document.services;

    // Validate recovery and update public keys.
    IonRequest.validateEs256kOperationPublicKey(recoveryKey);
    IonRequest.validateEs256kOperationPublicKey(updateKey);

    // Validate all given DID Document keys.
    IonRequest.validateDidDocumentKeys(didDocumentKeys);

    // Validate all given service.
    if (services !== undefined) {
      const serviceIdSet: Set<string> = new Set();
      for (const service of services) {
        IonRequest.validateService(service);
        if (serviceIdSet.has(service.id)) {
          throw new IonError(ErrorCode.DidDocumentServiceIdDuplicated, 'Service id has to be unique');
        }
        serviceIdSet.add(service.id);
      }
    }

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;

    const patches = [{
      action: 'replace',
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

  public static async createUpdateRequest (input: {
    didSuffix: string;
    updatePrivateKey: JwkEs256k;
    nextUpdatePublicKey: JwkEs256k;
    servicesToAdd?: any[];
    idsOfServicesToRemove?: string[];
  }): Promise<object> {
    const servicesToAdd = input.servicesToAdd;
    const idsOfServicesToRemove = input.idsOfServicesToRemove;

    const patches = [];

    if (servicesToAdd !== undefined && servicesToAdd.length > 0) {
      const patch = {
        action: PatchAction.AddServices,
        services: servicesToAdd
      };

      patches.push(patch);
    }

    if (idsOfServicesToRemove !== undefined && idsOfServicesToRemove.length > 0) {
      const patch = {
        action: PatchAction.RemoveServices,
        ids: idsOfServicesToRemove
      };

      patches.push(patch);
    }

    const updatePublicKey = {
      crv: input.updatePrivateKey.crv,
      kty: input.updatePrivateKey.kty,
      x: input.updatePrivateKey.x,
      y: input.updatePrivateKey.y,
    };

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;
    const revealValue = Multihash.canonicalizeThenHashThenEncode(updatePublicKey, hashAlgorithmInMultihashCode);

    const nextUpdateCommitmentHash = Multihash.canonicalizeThenDoubleHashThenEncode(input.nextUpdatePublicKey, hashAlgorithmInMultihashCode);
    const delta = {
      patches,
      updateCommitment: nextUpdateCommitmentHash
    };
    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const signedDataPayloadObject = {
      updateKey: updatePublicKey,
      deltaHash: deltaHash
    };
    const compactJws = await secp256k1.ES256K.sign(
      signedDataPayloadObject,
      input.updatePrivateKey,
      { alg: 'ES256K' }
    );

    const updateOperationRequest = {
      type: OperationType.Update,
      didSuffix: input.didSuffix,
      revealValue,
      delta,
      signedData: compactJws
    };

    return updateOperationRequest;
  }

  /**
   * Validates the schema of a ES256K JWK public key.
   */
  private static validateEs256kOperationPublicKey (publicKeyJwk: JwkEs256k) {
    const allowedProperties = new Set(['kty', 'crv', 'x', 'y']);
    for (const property in publicKeyJwk) {
      if (!allowedProperties.has(property)) {
        throw new IonError(ErrorCode.PublicKeyJwkEs256kHasUnexpectedProperty, `SECP256K1 JWK key has unexpected property '${property}'.`);
      }
    }

    if (publicKeyJwk.crv !== 'secp256k1') {
      throw new IonError(ErrorCode.JwkEs256kMissingOrInvalidCrv, `SECP256K1 JWK 'crv' property must be 'secp256k1' but got '${publicKeyJwk.crv}.'`);
    }

    if (publicKeyJwk.kty !== 'EC') {
      throw new IonError(ErrorCode.JwkEs256kMissingOrInvalidKty, `SECP256K1 JWK 'kty' property must be 'EC' but got '${publicKeyJwk.kty}.'`);
    }

    // `x` and `y` need 43 Base64URL encoded bytes to contain 256 bits.
    if (publicKeyJwk.x.length !== 43) {
      throw new IonError(ErrorCode.JwkEs256kHasIncorrectLengthOfX, `SECP256K1 JWK 'x' property must be 43 bytes.`);
    }

    if (publicKeyJwk.y.length !== 43) {
      throw new IonError(ErrorCode.JwkEs256kHasIncorrectLengthOfY, `SECP256K1 JWK 'y' property must be 43 bytes.`);
    }
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
