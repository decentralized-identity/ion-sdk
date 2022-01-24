import Encoder from './Encoder';
import IonDocumentModel from './models/IonDocumentModel';
import IonRequest from './IonRequest';
import IonSdkConfig from './IonSdkConfig';
import JsonCanonicalizer from './JsonCanonicalizer';
import JwkEd25519 from './models/JwkEd25519';
import JwkEs256k from './models/JwkEs256k';
import Multihash from './Multihash';

/**
 * Class containing DID related operations.
 */
export default class IonDid {
  /**
   * Creates a long-form DID.
   * @param input.document The initial state to be associate with the ION DID to be created using a `replace` document patch action.
   */
  public static createLongFormDid (input: {
    recoveryKey: JwkEs256k | JwkEd25519;
    updateKey: JwkEs256k | JwkEd25519;
    document: IonDocumentModel;
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
