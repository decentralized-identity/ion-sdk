import Encoder from './Encoder.js';
import ErrorCode from './ErrorCode.js';
import IonError from './IonError.js';
import IonSdkConfig from './IonSdkConfig.js';
import JsonCanonicalizer from './JsonCanonicalizer.js';
import { decode } from 'multiformats/hashes/digest';
import { sha256 } from 'multiformats/hashes/sha2';

/**
 * Class that performs hashing operations using the multihash format.
 */
export default class Multihash {
  /**
   * Multihashes the content using the hashing algorithm specified.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   * @returns A multihash of the content.
   */
  public static async hash (content: Uint8Array, hashAlgorithmInMultihashCode: number): Promise<Uint8Array> {
    let multihash: Uint8Array;
    switch (hashAlgorithmInMultihashCode) {
      case 18: // SHA256
        let hasher = await sha256.digest(content);
        multihash = hasher.bytes;
        break;
      default:
        throw new IonError(
          ErrorCode.MultihashUnsupportedHashAlgorithm,
          `Hash algorithm defined in multihash code ${hashAlgorithmInMultihashCode} is not supported.`
        );
    }
    
    return multihash;
  }

  /**
   * Hashes the content using the hashing algorithm specified as a generic (non-multihash) hash.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   * @returns A multihash bytes.
   */
  public static async hashAsNonMultihashBytes (content: Uint8Array, hashAlgorithmInMultihashCode: number): Promise<Uint8Array> {
    let hash;
    switch (hashAlgorithmInMultihashCode) {
      case 18: // SHA256
        hash = await sha256.encode(content);
        break;
      default:
        throw new IonError(
          ErrorCode.MultihashUnsupportedHashAlgorithm,
          `Hash algorithm defined in multihash code ${hashAlgorithmInMultihashCode} is not supported.`
        );
    }

    return hash;
  }

  /**
   * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
   * Mainly used for testing purposes.
   */
  public static async canonicalizeThenHashThenEncode (content: object, hashAlgorithmInMultihashCode: number): Promise<string> {
    const canonicalizedStringBytes = JsonCanonicalizer.canonicalizeAsBytes(content);

    const multihashEncodedString = await Multihash.hashThenEncode(canonicalizedStringBytes, hashAlgorithmInMultihashCode);
    return multihashEncodedString;
  }

  /**
   * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
   * Mainly used for testing purposes.
   */
  public static async canonicalizeThenDoubleHashThenEncode (content: object, hashAlgorithmInMultihashCode: number): Promise<string> {
    const contentBytes = JsonCanonicalizer.canonicalizeAsBytes(content);

    // Double hash.
    const intermediateHashBytes = await Multihash.hashAsNonMultihashBytes(contentBytes, hashAlgorithmInMultihashCode);
    const multihashEncodedString = await Multihash.hashThenEncode(intermediateHashBytes, hashAlgorithmInMultihashCode);
    return multihashEncodedString;
  }

  /**
   * Hashes the content using the hashing algorithm specified then encodes the multihash bytes as string.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   */
  public static async hashThenEncode (content: Uint8Array, hashAlgorithmInMultihashCode: number): Promise<string> {
    const multihashBytes = await Multihash.hash(content, hashAlgorithmInMultihashCode);
    const multihashEncodedString = Encoder.encode(multihashBytes);
    return multihashEncodedString;
  }

  /**
   * Checks if the given encoded hash is a multihash computed using the configured hashing algorithm.
   */
  public static validateEncodedHashComputedUsingSupportedHashAlgorithm (
    encodedMultihash: string, // didSuffix
    inputContextForErrorLogging: string
  ) {
    let multihash;
    const multihashBytes = Encoder.decodeAsBytes(encodedMultihash, inputContextForErrorLogging);
    try {
      multihash = decode(multihashBytes);
    } catch {
      throw new IonError(
        ErrorCode.MultihashStringNotAMultihash,
        `Given ${inputContextForErrorLogging} string '${encodedMultihash}' is not a multihash after decoding.`);
    }

    const hashAlgorithmInMultihashCode = IonSdkConfig.hashAlgorithmInMultihashCode;

    if (hashAlgorithmInMultihashCode !== multihash.code) {
      throw new IonError(
        ErrorCode.MultihashUnsupportedHashAlgorithm,
        `Given ${inputContextForErrorLogging} uses unsupported multihash algorithm with code ${multihash.code}, ` +
        `should use ${hashAlgorithmInMultihashCode} or change IonSdkConfig to desired hashing algorithm.`
      );
    }
  }
}
