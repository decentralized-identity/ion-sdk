import ErrorCode from './ErrorCode.js';
import IonError from './IonError.js';
import { base64url } from 'multiformats/bases/base64';

/**
 * Class that encodes binary blobs into strings.
 * Note that the encode/decode methods may change underlying encoding scheme.
 */
export default class Encoder {
  /**
   * Encodes given bytes into a Base64URL string.
   */
  public static encode (content: Uint8Array): string {
    const encodedContent = base64url.baseEncode(content);
    return encodedContent;
  }

  /**
   * Decodes the given Base64URL string into bytes.
   */
  public static decodeAsBytes (encodedContent: string, inputContextForErrorLogging: string): Uint8Array {
    if (!Encoder.isBase64UrlString(encodedContent)) {
      throw new IonError(ErrorCode.EncodedStringIncorrectEncoding, `Given ${inputContextForErrorLogging} must be base64url string.`);
    }

    return base64url.baseDecode(encodedContent);
  }

  /**
   * Decodes the given Base64URL string into the original string.
   */
  public static decodeAsString (encodedContent: string, inputContextForErrorLogging: string): string {
    const rawBytes = Encoder.decodeAsBytes(encodedContent, inputContextForErrorLogging);

    return Encoder.bytesToString(rawBytes);
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

  /**
   * Converts input string to bytes.
   */
  public static stringToBytes (input: string): Uint8Array {
    const bytes = new TextEncoder().encode(input);
    return bytes;
  }

  /**
   * Converts bytes to string.
   */
  public static bytesToString (input: Uint8Array): string {
    const output = new TextDecoder().decode(input);
    return output;
  }
}
