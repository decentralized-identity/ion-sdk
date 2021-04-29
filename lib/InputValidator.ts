import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';
import Multihash from './Multihash';

/**
 * Class containing input validation methods.
 */
export default class InputValidator {
  /**
   * Validates that the given input is a multihash computed using a configured hash algorithm.
   */
  public static validateEncodedMultihash (input: string, inputContextForErrorLogging: string) {
    Multihash.validateHashComputedUsingSupportedHashAlgorithm(input, inputContextForErrorLogging);
  }

  /**
   * Validates an `id` property (in `IonPublicKeyModel` and `IonServiceModel`).
   */
  public static validateId (id: string) {
    const maxIdLength = 50;
    if (id.length > maxIdLength) {
      throw new IonError(ErrorCode.IdTooLong, `Key ID length ${id.length} exceed max allowed length of ${maxIdLength}.`);
    }

    if (!Encoder.isBase64UrlString(id)) {
      throw new IonError(ErrorCode.IdNotUsingBase64UrlCharacterSet, `Key ID '${id}' is not a Base64URL string.`);
    }
  }

  /**
   * Validates the given public key purposes.
   */
  public static validatePublicKeyPurposes (purposes?: IonPublicKeyPurpose[]) {
    // Nothing to validate if `purposes` is undefined.
    if (purposes === undefined) {
      return;
    }

    // Validate that all purposes are be unique.
    const processedPurposes: Set<IonPublicKeyPurpose> = new Set();
    for (const purpose of purposes) {
      if (processedPurposes.has(purpose)) {
        throw new IonError(ErrorCode.PublicKeyPurposeDuplicated, `Public key purpose '${purpose}' already specified.`);
      }
      processedPurposes.add(purpose);
    }
  }
}
