import Encoder from "./Encoder";
import JsonCanonicalizer from "./JsonCanonicalizer";
import JwkEs256k from "./JwkEs256k";
import Multihash from './Multihash';
import PublicKeyModel from "./PublicKeyModel";
import SdkConfig from "./SdkConfig";
import ServiceEndpointModel from "./ServiceEndpointModel";

/**
 * Class containing reusable DID related operations.
 */
export default class SidetreeDid {
  /**
   * Creates a long-form DID.
   * @param otherPublicKeys Public keys to be included in the resolved DID Document.
   * @param serviceEndpoints  Service endpoints to be included in the resolved DID Document.
   */
  public static createLongFormDid (
    recoveryPublicKey: JwkEs256k,
    updatePublicKey: JwkEs256k,
    otherPublicKeys: PublicKeyModel[],
    serviceEndpoints: ServiceEndpointModel[]): string {

    const hashAlgorithmInMultihashCode = SdkConfig.hashAlgorithmInMultihashCode

    const document = {
      public_keys: otherPublicKeys,
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

    // const deltaBuffer = Buffer.from(JSON.stringify(delta));
    // const deltaHash = Encoder.encode(Multihash.hash(deltaBuffer));

    const deltaHash = Multihash.canonicalizeThenHashThenEncode(delta, hashAlgorithmInMultihashCode);

    const suffixData = {
      delta_hash: deltaHash,
      recovery_commitment: Multihash.canonicalizeThenDoubleHashThenEncode(recoveryPublicKey, hashAlgorithmInMultihashCode)
    };

    const didUniqueSuffix = SidetreeDid.computeDidUniqueSuffix(suffixData);
    const shortFormDid = `did:${SdkConfig.didMethodName}:${didUniqueSuffix}`;

    // TODO: discuss if canonicalization is necessary.
    const initialState = {
      suffix_data: suffixData,
      delta: delta
    };

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
    const multihash = Multihash.hash(canonicalizedStringBuffer, SdkConfig.hashAlgorithmInMultihashCode);
    const encodedMultihash = Encoder.encode(multihash);
    return encodedMultihash;
  }
}
