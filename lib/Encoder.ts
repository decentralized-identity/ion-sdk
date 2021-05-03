import { b64fromBuffer, b64fromURLSafe, b64toURLSafe } from '@waiting/base64';
import ErrorCode from './ErrorCode';
import IonError from './IonError';

/**
 * Class that encodes binary blobs into strings.
 * Note that the encode/decode methods may change underlying encoding scheme.
 */
export default class Encoder {
  /**
   * Encodes given Buffer into a Base64URL string.
   */
  public static encode (content: Buffer): string {
    const encodedContent = b64toURLSafe(b64fromBuffer(content));
    return encodedContent;
  }

  /**
   * Decodes the given Base64URL string into a Buffer.
   */
  public static decodeAsBuffer (encodedContent: string, inputContextForErrorLogging: string): Buffer {
    if (!Encoder.isBase64UrlString(encodedContent)) {
      throw new IonError(ErrorCode.EncodedMultiHashIncorrectEncoding, `Given ${inputContextForErrorLogging} must be base64url string.`);
    }
    // Turns the encoded string to regular base 64 and then decode as buffer
    return Buffer.from(b64fromURLSafe(encodedContent), 'base64');
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
