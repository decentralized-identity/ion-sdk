/**
 * Global configuration of the SDK.
 */
export default class SdkConfig {
  /**
   * Network name in ION DID, okay to leave as `undefined` if mainnet.
   */
  public static network: string | undefined;

  /**
   * Default hash algorithm used when hashing is performed.
   */
  public static hashAlgorithmInMultihashCode = 18; // SHA256
}
