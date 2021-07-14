/**
 * Interface for signing an arbitrary object.
 */
export default interface ISigner {
  /**
   * Signs the given content as a compact JWS string.
   */
  sign (header: object, content: object): Promise<string>;
}
