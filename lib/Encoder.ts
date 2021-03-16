import { b64fromBuffer, b64urlEncode, b64toURLSafe } from '@waiting/base64';

/**
 * Class that encodes binary blobs into strings.
 * Note that the encode/decode methods may change underlying encoding scheme.
 */
export default class Encoder {
  /**
   * Encodes given Buffer into a Base64URL string.
   */
  public static encode (content: Buffer | string): string {
    const encodedContent = b64toURLSafe(content instanceof Buffer ? b64fromBuffer(content) : b64urlEncode(content));
    return encodedContent;
  }

  /**
   * Tests if the given string is a Base64URL string.
   */
  public static isBase64UrlString (input: string): boolean {
    // NOTE:
    // /<expression>/ denotes regex.
    // ^ denotes beginning of string.
    // $ denotes end of string.
    // + denotes one or more characters.
    const isBase64UrlString = /^[A-Za-z0-9_-]+$/.test(input);
    return isBase64UrlString;
  }
}
