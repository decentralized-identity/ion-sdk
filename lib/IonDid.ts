import Encoder from './Encoder';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonRequest from './IonRequest';
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
   * @param services Services to be included in the resolved DID Document.
   */
  public static createLongFormDid (input: {
    recoveryKey: JwkEs256k;
    updateKey: JwkEs256k;
    didDocumentKeys: IonPublicKeyModel[];
    services: IonServiceModel[];
  }): string {
    const createRequest = IonRequest.createCreateRequest(input);

    const didUniqueSuffix = IonDid.computeDidUniqueSuffix(createRequest.suffixData);

    // Add the network portion if not configured for mainnet.
    let shortFormDid;
    if (IonSdkConfig.network === undefined || IonSdkConfig.network === 'mainnet') {
      shortFormDid = `did:ion:${didUniqueSuffix}`;
    } else {
      shortFormDid = `did:ion:${IonSdkConfig.network}:${didUniqueSuffix}`;
    }

    const initialState = {
      suffixData: createRequest.suffixData,
      delta: createRequest.delta
    };

    // Initial state must be canonicalized as per spec.
    const canonicalizedInitialStateBuffer = JsonCanonicalizer.canonicalizeAsBuffer(initialState);
    const encodedCanonicalizedInitialStateString = Encoder.encode(canonicalizedInitialStateBuffer);

    const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
    return longFormDid;
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
