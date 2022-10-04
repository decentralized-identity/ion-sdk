import * as multihashes from 'multihashes';
import * as shajs from 'sha.js';
import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import { HashCode } from 'multihashes';
import IonError from './IonError';
import IonSdkConfig from './IonSdkConfig';
import JsonCanonicalizer from './JsonCanonicalizer';

/**
 * Class that performs hashing operations using the multihash format.
 */
export default class Multihash {
  /**
   * Hashes the content using the hashing algorithm specified.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   */
  public static hash (content: Uint8Array, hashAlgorithmInMultihashCode: number): Uint8Array {
    const conventionalHash = this.hashAsNonMultihashBytes(content, hashAlgorithmInMultihashCode);
    const multihash = multihashes.encode(conventionalHash, hashAlgorithmInMultihashCode as HashCode);

    return multihash;
  }

  /**
   * Hashes the content using the hashing algorithm specified as a generic (non-multihash) hash.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   * @returns A multihash bytes.
   */
  public static hashAsNonMultihashBytes (content: Uint8Array, hashAlgorithmInMultihashCode: number): Uint8Array {
    let hash;
    switch (hashAlgorithmInMultihashCode) {
      case 18: // SHA256
        hash = shajs('sha256').update(content).digest();
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
  public static canonicalizeThenHashThenEncode (content: object, hashAlgorithmInMultihashCode: number) {
    const canonicalizedStringBytes = JsonCanonicalizer.canonicalizeAsBytes(content);

    const multihashEncodedString = Multihash.hashThenEncode(canonicalizedStringBytes, hashAlgorithmInMultihashCode);
    return multihashEncodedString;
  }

  /**
   * Canonicalize the given content, then double hashes the result using the latest supported hash algorithm, then encodes the multihash.
   * Mainly used for testing purposes.
   */
  public static canonicalizeThenDoubleHashThenEncode (content: object, hashAlgorithmInMultihashCode: number) {
    const contentBytes = JsonCanonicalizer.canonicalizeAsBytes(content);

    // Double hash.
    const intermediateHashBytes = Multihash.hashAsNonMultihashBytes(contentBytes, hashAlgorithmInMultihashCode);
    const multihashEncodedString = Multihash.hashThenEncode(intermediateHashBytes, hashAlgorithmInMultihashCode);
    return multihashEncodedString;
  }

  /**
   * Hashes the content using the hashing algorithm specified then encodes the multihash bytes as string.
   * @param hashAlgorithmInMultihashCode The hashing algorithm to use.
   */
  public static hashThenEncode (content: Uint8Array, hashAlgorithmInMultihashCode: number): string {
    const multihashBytes = Multihash.hash(content, hashAlgorithmInMultihashCode);
    const multihashEncodedString = Encoder.encode(multihashBytes);
    return multihashEncodedString;
  }

  /**
   * Checks if the given encoded hash is a multihash computed using the configured hashing algorithm.
   */
  public static validateEncodedHashComputedUsingSupportedHashAlgorithm (
    encodedMultihash: string,
    inputContextForErrorLogging: string
  ) {
    let multihash;
    const multihashBytes = Encoder.decodeAsBytes(encodedMultihash, inputContextForErrorLogging);
    try {
      multihash = multihashes.decode(multihashBytes);
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
