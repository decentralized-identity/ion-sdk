import Encoder from './Encoder.js';
import IonDocumentModel from './models/IonDocumentModel.js';
import IonRequest from './IonRequest.js';
import IonSdkConfig from './IonSdkConfig.js';
import JsonCanonicalizer from './JsonCanonicalizer.js';
import JwkEs256k from './models/JwkEs256k.js';
import Multihash from './Multihash.js';

/**
 * Class containing DID related operations.
 */
export default class IonDid {
  /**
   * Creates a long-form DID.
   * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
   */
  public static async createLongFormDid (input: {
    recoveryKey: JwkEs256k;
    updateKey: JwkEs256k;
    document: IonDocumentModel;
  }): Promise<string> {
    const createRequest = await IonRequest.createCreateRequest(input);

    const didUniqueSuffix = await IonDid.computeDidUniqueSuffix(createRequest.suffixData);

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
    const canonicalizedInitialStateBytes = JsonCanonicalizer.canonicalizeAsBytes(initialState);
    const encodedCanonicalizedInitialStateString = Encoder.encode(canonicalizedInitialStateBytes);

    const longFormDid = `${shortFormDid}:${encodedCanonicalizedInitialStateString}`;
    return longFormDid;
  }

  /**
   * Computes the DID unique suffix given the encoded suffix data string.
   */
  private static async computeDidUniqueSuffix (suffixData: object): Promise<string> {
    const canonicalizedStringBytes = JsonCanonicalizer.canonicalizeAsBytes(suffixData);
    const multihash = await Multihash.hash(canonicalizedStringBytes, IonSdkConfig.hashAlgorithmInMultihashCode);
    const encodedMultihash = Encoder.encode(multihash);
    return encodedMultihash;
  }
}
