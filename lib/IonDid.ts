import DidDocumentKeyModel from './models/DidDocumentKeyModel';
import DidDocumentKeyValidator from './DidDocumentKeyValidator';
import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonSdkConfig from './IonSdkConfig';
import JsonCanonicalizer from './JsonCanonicalizer';
import JwkEs256k from './models/JwkEs256k';
import Multihash from './Multihash';
import ServiceEndpointModel from './models/ServiceEndpointModel';

/**
 * Class containing DID related operations.
 */
export default class IonDid {
  /**
   * Creates a long-form DID.
   * @param didDocumentKeys Public keys to be included in the resolved DID Document.
   * @param serviceEndpoints  Service endpoints to be included in the resolved DID Document.
   */
  public static createLongFormDid (input: {
    recoveryKey: JwkEs256k;
    updateKey: JwkEs256k;
    didDocumentKeys: DidDocumentKeyModel[];
    serviceEndpoints: ServiceEndpointModel[];
  }): string {
    const recoveryKey = input.recoveryKey;
    const updateKey = input.updateKey;
    const didDocumentKeys = input.didDocumentKeys;
    const serviceEndpoints = input.serviceEndpoints;

    // Validate recovery and update public keys.
    IonDid.validateEs256kOperationPublicKey(recoveryKey);
    IonDid.validateEs256kOperationPublicKey(updateKey);

    // Validate all given DID Document keys.
    IonDid.validateDidDocumentKeys(didDocumentKeys);

    // Validate all given service endpoints.
    for (const serviceEndpoint of serviceEndpoints) {
      IonDid.validateServiceEndpoint(serviceEndpoint);
    }

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;

    const document = {
      public_keys: didDocumentKeys,
      service_endpoints: serviceEndpoints
    };

    const patches = [{
      action: 'replace',
      document
    }];

    const delta = {
      update_commitment: Multihash.canonicalizeThenDoubleHashThenEncode(updateKey, hashAlgorithmInMultihashCode),
      patches
    };

    IonDid.validateDeltaSize(delta);

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const suffixData = {
      delta_hash: deltaHash,
      recovery_commitment: Multihash.canonicalizeThenDoubleHashThenEncode(recoveryKey, hashAlgorithmInMultihashCode)
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
      suffix_data: suffixData,
      delta: delta
    };

    // Initial state must be canonicalized as per spec.
    const canonicalizedInitialStateBuffer = JsonCanonicalizer.canonicalizeAsBuffer(initialState);
    const encodedCanonicalizedInitialStateString = Encoder.encode(canonicalizedInitialStateBuffer);

    const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
    return longFormDid;
  }

  private static validateEs256kOperationPublicKey (jwk: JwkEs256k) {
    const allowedProperties = new Set(['kty', 'crv', 'x', 'y']);
    for (let property in jwk) {
      if (!allowedProperties.has(property)) {
        throw new IonError(ErrorCode.IonDidEs256kJwkHasUnexpectedProperty, `SECP256K1 JWK key has unexpected property '${property}'.`);
      }
    }

    if (jwk.crv !== 'secp256k1') {
      throw new IonError(ErrorCode.IonDidEs256kJwkMissingOrInvalidCrv, `SECP256K1 JWK 'crv' property must be 'secp256k1' but got '${jwk.crv}.'`);
    }

    if (jwk.kty !== 'EC') {
      throw new IonError(ErrorCode.IonDidEs256kJwkMissingOrInvalidKty, `SECP256K1 JWK 'kty' property must be 'EC' but got '${jwk.kty}.'`);
    }

    // `x` and `y` need 43 Base64URL encoded bytes to contain 256 bits.
    if (jwk.x.length !== 43) {
      throw new IonError(ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfX, `SECP256K1 JWK 'x' property must be 43 bytes.`);
    }

    if (jwk.y.length !== 43) {
      throw new IonError(ErrorCode.IonDidEs256kJwkHasIncorrectLengthOfY, `SECP256K1 JWK 'y' property must be 43 bytes.`);
    }
  }

  private static validateDidDocumentKeys (publicKeys: DidDocumentKeyModel[]) {
    // Validate each public key.
    const publicKeyIdSet: Set<string> = new Set();
    for (let publicKey of publicKeys) {
      if (Array.isArray(publicKey.jwk)) {
        throw new IonError(ErrorCode.IonDidDocumentPublicKeyMissingOrIncorrectType, `DID Document key 'jwk' property is not a non-array object.`);
      }

      DidDocumentKeyValidator.validateId(publicKey.id);

      // 'id' must be unique across all given keys.
      if (publicKeyIdSet.has(publicKey.id)) {
        throw new IonError(ErrorCode.IonDidDocumentPublicKeyIdDuplicated, `DID Document key with ID '${publicKey.id}' already exists.`);
      }
      publicKeyIdSet.add(publicKey.id);

      DidDocumentKeyValidator.validatePurposes(publicKey.purpose);
    }
  }

  private static validateServiceEndpoint (serviceEndpoint: ServiceEndpointModel) {
    const maxIdLength = 50;
    if (serviceEndpoint.id.length > maxIdLength) {
      const errorMessage = `Service endpoint id length ${serviceEndpoint.id.length} exceeds max allowed length of ${maxIdLength}.`;
      throw new IonError(ErrorCode.IonDidServiceEndpointIdTooLong, errorMessage);
    }

    if (!Encoder.isBase64UrlString(serviceEndpoint.id)) {
      throw new IonError(ErrorCode.IonDidServiceEndpointIdNotInBase64UrlCharacterSet, `Service endpoint ID '${serviceEndpoint.id}' is not a Base64URL string.`);
    }

    const maxTypeLength = 30;
    if (serviceEndpoint.type.length > maxTypeLength) {
      const errorMessage = `Service endpoint type length ${serviceEndpoint.type.length} exceeds max allowed length of ${maxTypeLength}.`;
      throw new IonError(ErrorCode.IonDidServiceEndpointTypeTooLong, errorMessage);
    }

    // Throw error if `endpoint` is an array.
    if (Array.isArray(serviceEndpoint.endpoint)) {
      const errorMessage = 'Service endpoint value cannot be an array.';
      throw new IonError(ErrorCode.IonDidServiceEndpointValueCannotBeAnArray, errorMessage);
    }

    if (typeof serviceEndpoint.endpoint === 'string') {
      try {
        // Validating endpoint string is a URL, no need to assign to a variable, it will throw if not valid.
        // tslint:disable-next-line
        new URL(serviceEndpoint.endpoint);
      } catch {
        throw new IonError(ErrorCode.IonDidServiceEndpointStringNotValidUrl, `Service endpoint string '${serviceEndpoint.endpoint}' is not a URL.`);
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
