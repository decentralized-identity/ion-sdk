import IonNetwork from './enums/IonNetwork.js';

/**
 * Global configuration of the SDK.
 */
export default class IonSdkConfig {
  /**
   * Default hash algorithm used when hashing is performed.
   */
  public static hashAlgorithmInMultihashCode = 18; // SHA256

  /**
   * Maximum bytes for canonicalized delta.
   */
  public static maxCanonicalizedDeltaSizeInBytes: number = 1000;

  /**
   * Network name in ION DID, okay to leave as `undefined` if mainnet.
   */
  public static network: IonNetwork | undefined;
}
