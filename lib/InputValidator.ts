import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';

/**
 * Class containing input validation methods.
 */
export default class InputValidator {
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
  public static validatePublicKeyPurposes (purposes: IonPublicKeyPurpose[]) {
    if (purposes.length === 0) {
      throw new IonError(ErrorCode.PublicKeyPurposeNotDefined, `Public key 'purpose' is not defined.`);
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
