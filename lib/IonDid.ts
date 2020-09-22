import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import JsonCanonicalizer from './JsonCanonicalizer';
import JwkEs256k from './models/JwkEs256k';
import Multihash from './Multihash';
import PublicKeyModel from './models/PublicKeyModel';
import SdkConfig from './SdkConfig';
import ServiceEndpointModel from './models/ServiceEndpointModel';
import IonError from './IonError';
import IonKeyInternal from './IonKeyInternal';

/**
 * Class containing reusable DID related operations.
 */
export default class IonDid {
  /**
   * Creates a long-form DID.
   * @param didDocumentPublicKeys Public keys to be included in the resolved DID Document.
   * @param serviceEndpoints  Service endpoints to be included in the resolved DID Document.
   */
  public static createLongFormDid (
    recoveryPublicKey: JwkEs256k,
    updatePublicKey: JwkEs256k,
    didDocumentPublicKeys: PublicKeyModel[],
    serviceEndpoints: ServiceEndpointModel[]): string {

    // Validate all given DID Document keys.
    for (const key of didDocumentPublicKeys) {
      IonDid.validateDidDocumentPublicKey(key);
    }

    // Validate all given service endpoints.
    for (const serviceEndpoint of serviceEndpoints) {
      IonDid.validateServiceEndpoint(serviceEndpoint);
    }

    const hashAlgorithmInMultihashCode = SdkConfig.hashAlgorithmInMultihashCode;

    const document = {
      public_keys: didDocumentPublicKeys,
      service_endpoints: serviceEndpoints
    };

    const patches = [{
      action: 'replace',
      document
    }];

    const delta = {
      update_commitment: Multihash.canonicalizeThenDoubleHashThenEncode(updatePublicKey, hashAlgorithmInMultihashCode),
      patches
    };

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const suffixData = {
      delta_hash: deltaHash,
      recovery_commitment: Multihash.canonicalizeThenDoubleHashThenEncode(recoveryPublicKey, hashAlgorithmInMultihashCode)
    };

    const didUniqueSuffix = IonDid.computeDidUniqueSuffix(suffixData);

    // Add the network portion if not configured for mainnet.
    let shortFormDid;
    if (SdkConfig.network === undefined || SdkConfig.network === 'mainnet') {
      shortFormDid = `did:ion:${didUniqueSuffix}`;
    } else {
      shortFormDid = `did:ion:${SdkConfig.network}:${didUniqueSuffix}`;
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

  private static validateDidDocumentPublicKey (publicKey: PublicKeyModel) {
    IonKeyInternal.validateId(publicKey.id);
    IonKeyInternal.validatePurposes(publicKey.purpose);
  }

  private static validateServiceEndpoint (serviceEndpoint: ServiceEndpointModel) {
    const maxTypeLength = 30;
    if (serviceEndpoint.type.length > maxTypeLength) {
      throw new IonError(
        ErrorCode.IonDidServiceEndpointTypeTooLong,
        `Service endpoint type length ${serviceEndpoint.type.length} exceeds max allowed length of ${maxTypeLength}.`
      );
    }

    const maxEndpointLength = 100;
    if (serviceEndpoint.endpoint.length > maxEndpointLength) {
      throw new IonError(
        ErrorCode.IonDidServiceEndpointTooLong,
        `Service endpoint length ${serviceEndpoint.endpoint.length} exceeds max allowed length of ${maxEndpointLength}.`
      );
    }

    try {
      // Validating endpoint is a URL, no need to assign to a variable, it will throw if not valid.
      // tslint:disable-next-line
      new URL(serviceEndpoint.endpoint);
    } catch {
      throw new IonError(
        ErrorCode.IonDidServiceEndpointNotValidUrl,
        `Service endpoint '${serviceEndpoint.endpoint}' is not a URL.`);
    }
  }

  /**
   * Computes the DID unique suffix given the encoded suffix data string.
   */
  private static computeDidUniqueSuffix (suffixData: object): string {
    const canonicalizedStringBuffer = JsonCanonicalizer.canonicalizeAsBuffer(suffixData);
    const multihash = Multihash.hash(canonicalizedStringBuffer, SdkConfig.hashAlgorithmInMultihashCode);
    const encodedMultihash = Encoder.encode(multihash);
    return encodedMultihash;
  }
}
