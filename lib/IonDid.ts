import * as URI from 'uri-js';
import DidDocumentKeyModel from './models/DidDocumentKeyModel';
import DidDocumentKeyValidator from './DidDocumentKeyValidator';
import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonSdkConfig from './IonSdkConfig';
import IonServiceModel from './models/IonServiceModel';
import JsonCanonicalizer from './JsonCanonicalizer';
import JwkEs256k from './models/JwkEs256k';
import Multihash from './Multihash';

/**
 * Class containing DID related operations.
 */
export default class IonDid {
  /**
   * Creates a long-form DID.
   * @param didDocumentKeys Public keys to be included in the resolved DID Document.
   * @param services  Services to be included in the resolved DID Document.
   */
  public static createLongFormDid (input: {
    recoveryKey: JwkEs256k;
    updateKey: JwkEs256k;
    didDocumentKeys: DidDocumentKeyModel[];
    services: IonServiceModel[];
  }): string {
    const recoveryKey = input.recoveryKey;
    const updateKey = input.updateKey;
    const didDocumentKeys = input.didDocumentKeys;
    const services = input.services;

    // Validate recovery and update public keys.
    IonDid.validateEs256kOperationPublicKey(recoveryKey);
    IonDid.validateEs256kOperationPublicKey(updateKey);

    // Validate all given DID Document keys.
    IonDid.validateDidDocumentKeys(didDocumentKeys);

    // Validate all given service.
    for (const service of services) {
      IonDid.validateService(service);
    }

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;

    const document = {
      publicKeys: didDocumentKeys,
      services
    };

    const patches = [{
      action: 'replace',
      document
    }];

    const delta = {
      updateCommitment: Multihash.canonicalizeThenDoubleHashThenEncode(updateKey, hashAlgorithmInMultihashCode),
      patches
    };

    IonDid.validateDeltaSize(delta);

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const suffixData = {
      deltaHash,
      recoveryCommitment: Multihash.canonicalizeThenDoubleHashThenEncode(recoveryKey, hashAlgorithmInMultihashCode)
    };

    const didUniqueSuffix = IonDid.computeDidUniqueSuffix(suffixData);

    // Add the network portion if not configured for mainnet.
    let shortFormDid;
    if (IonSdkConfig.network === undefined || IonSdkConfig.network === 'mainnet') {
      shortFormDid = `did:ion:${didUniqueSuffix}`;
    } else {
      shortFormDid = `did:ion:${IonSdkConfig.network}:${didUniqueSuffix}`;
    }

    const initialState = {
      suffixData,
      delta
    };

    // Initial state must be canonicalized as per spec.
    const canonicalizedInitialStateBuffer = JsonCanonicalizer.canonicalizeAsBuffer(initialState);
    const encodedCanonicalizedInitialStateString = Encoder.encode(canonicalizedInitialStateBuffer);

    const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
    return longFormDid;
  }

  private static validateEs256kOperationPublicKey (publicKeyJwk: JwkEs256k) {
    const allowedProperties = new Set(['kty', 'crv', 'x', 'y']);
    for (const property in publicKeyJwk) {
      if (!allowedProperties.has(property)) {
        throw new IonError(ErrorCode.IonDidEs256kJwkHasUnexpectedProperty, `SECP256K1 JWK key has unexpected property '${property}'.`);
      }
    }

    if (publicKeyJwk.crv !== 'secp256k1') {
      throw new IonError(ErrorCode.IonDidEs256kJwkMissingOrInvalidCrv, `SECP256K1 JWK 'crv' property must be 'secp256k1' but got '${publicKeyJwk.crv}.'`);
    }

    if (publicKeyJwk.kty !== 'EC') {
      throw new IonError(ErrorCode.IonDidEs256kJwkMissingOrInvalidKty, `SECP256K1 JWK 'kty' property must be 'EC' but got '${publicKeyJwk.kty}.'`);
    }

    // `x` and `y` need 43 Base64URL encoded bytes to contain 256 bits.
    if (publicKeyJwk.x.length !== 43) {
      throw new IonError(ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfX, `SECP256K1 JWK 'x' property must be 43 bytes.`);
    }

    if (publicKeyJwk.y.length !== 43) {
      throw new IonError(ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfY, `SECP256K1 JWK 'y' property must be 43 bytes.`);
    }
  }

  private static validateDidDocumentKeys (publicKeys: DidDocumentKeyModel[]) {
    // Validate each public key.
    const publicKeyIdSet: Set<string> = new Set();
    for (const publicKey of publicKeys) {
      if (Array.isArray(publicKey.publicKeyJwk)) {
        throw new IonError(ErrorCode.IonDidDocumentPublicKeyMissingOrIncorrectType, `DID Document key 'publicKeyJwk' property is not a non-array object.`);
      }

      DidDocumentKeyValidator.validateId(publicKey.id);

      // 'id' must be unique across all given keys.
      if (publicKeyIdSet.has(publicKey.id)) {
        throw new IonError(ErrorCode.IonDidDocumentPublicKeyIdDuplicated, `DID Document key with ID '${publicKey.id}' already exists.`);
      }
      publicKeyIdSet.add(publicKey.id);

      DidDocumentKeyValidator.validatePurposes(publicKey.purposes);
    }
  }

  private static validateService (service: IonServiceModel) {
    const maxIdLength = 50;
    if (service.id.length > maxIdLength) {
      const errorMessage = `Service endpoint id length ${service.id.length} exceeds max allowed length of ${maxIdLength}.`;
      throw new IonError(ErrorCode.IonDidServiceIdTooLong, errorMessage);
    }

    if (!Encoder.isBase64UrlString(service.id)) {
      throw new IonError(ErrorCode.IonDidServiceIdNotInBase64UrlCharacterSet, `Service endpoint ID '${service.id}' is not a Base64URL string.`);
    }

    const maxTypeLength = 30;
    if (service.type.length > maxTypeLength) {
      const errorMessage = `Service endpoint type length ${service.type.length} exceeds max allowed length of ${maxTypeLength}.`;
      throw new IonError(ErrorCode.IonDidServiceTypeTooLong, errorMessage);
    }

    // Throw error if `serviceEndpoint` is an array.
    if (Array.isArray(service.serviceEndpoint)) {
      const errorMessage = 'Service endpoint value cannot be an array.';
      throw new IonError(ErrorCode.IonDidServiceEndpointValueCannotBeAnArray, errorMessage);
    }

    if (typeof service.serviceEndpoint === 'string') {
      const uri = URI.parse(service.serviceEndpoint);
      if (uri.error !== undefined) {
        throw new IonError(ErrorCode.IonDidServiceEndpointStringNotValidUrl, `Service endpoint string '${service.serviceEndpoint}' is not a URL.`);
      }
    }
  }

  private static validateDeltaSize (delta: object) {
    const deltaBuffer = JsonCanonicalizer.canonicalizeAsBuffer(delta);
    if (deltaBuffer.length > IonSdkConfig.maxCanonicalizedDeltaSizeInBytes) {
      const errorMessage = `Delta of ${deltaBuffer.length} bytes exceeded limit of ${IonSdkConfig.maxCanonicalizedDeltaSizeInBytes} bytes.`;
      throw new IonError(ErrorCode.IonDidDeltaExceedsMaximumSize, errorMessage);
    }
  }

  /**
   * Computes the DID unique suffix given the encoded suffix data string.
   */
  private static computeDidUniqueSuffix (suffixData: object): string {
    const canonicalizedStringBuffer = JsonCanonicalizer.canonicalizeAsBuffer(suffixData);
    const multihash = Multihash.hash(canonicalizedStringBuffer, IonSdkConfig.hashAlgorithmInMultihashCode);
    const encodedMultihash = Encoder.encode(multihash);
    return encodedMultihash;
  }
}
