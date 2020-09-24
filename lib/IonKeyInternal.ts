import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import PublicKeyPurpose from './models/PublicKeyPurpose';

/**
 * Internal class containing operations related to ION keys.
 * Not exposed as part of the external facing SDK.
 */
export default class IonKeyInternal {
  /**
   * Validates the given public key ID.
   */
  public static validateId (id: string) {
    const maxIdLength = 50;
    if (id.length > maxIdLength) {
      throw new IonError(ErrorCode.IonKeyIdTooLong, `Key ID length ${id.length} exceed max allowed length of ${maxIdLength}`);
    }

    if (!Encoder.isBase64UrlString(id)) {
      throw new IonError(ErrorCode.IonKeyIdNotUsingBase64UrlCharacterSet, `Key ID '${id}' is a Base64URL string.`);
    }
  }

  /**
   * Validates the given key purposes.
   */
  public static validatePurposes (purposes: any) {
    if (!Array.isArray(purposes)) {
      throw new IonError(ErrorCode.IonKeyPurposeNotAnArray, `ION key 'purpose' not an array.`);
    }

    if (purposes.length === 0) {
      throw new IonError(ErrorCode.IonKeyPurposeNotDefined, `ION key 'purpose' is not defined.`);
    }

    const validPurposes = new Set(Object.values(PublicKeyPurpose));

    // Validate each purpose.
    const processedPurposes: Set<PublicKeyPurpose> = new Set();
    for (const purpose of purposes) {
      // Must be a valid purpose.
      if (!validPurposes.has(purpose)) {
        throw new IonError(ErrorCode.IonKeyPurposeInvalid, `ION key purpose '${purpose}' is not valid.`);
      }

      // All purposes must be unique.
      if (processedPurposes.has(purpose)) {
        throw new IonError(ErrorCode.IonKeyPurposeDuplicated, `ION key purpose '${purpose}' already specified.`);
      }
      processedPurposes.add(purpose);
    }
  }
}
