import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';

/**
 * Class containing operations related to keys specified within a DID Document.
 */
export default class IonPublicKeyValidator {
  /**
   * Validates the given public key ID.
   */
  public static validateId (id: string) {
    const maxIdLength = 50;
    if (id.length > maxIdLength) {
      throw new IonError(ErrorCode.IonKeyIdTooLong, `Key ID length ${id.length} exceed max allowed length of ${maxIdLength}.`);
    }

    if (!Encoder.isBase64UrlString(id)) {
      throw new IonError(ErrorCode.IonKeyIdNotUsingBase64UrlCharacterSet, `Key ID '${id}' is not a Base64URL string.`);
    }
  }

  /**
   * Validates the given key purposes.
   */
  public static validatePurposes (purposes: IonPublicKeyPurpose[]) {
    if (purposes.length === 0) {
      throw new IonError(ErrorCode.IonKeyPurposeNotDefined, `ION key 'purpose' is not defined.`);
    }

    // Validate that all purposes are be unique.
    const processedPurposes: Set<IonPublicKeyPurpose> = new Set();
    for (const purpose of purposes) {
      if (processedPurposes.has(purpose)) {
        throw new IonError(ErrorCode.IonKeyPurposeDuplicated, `ION key purpose '${purpose}' already specified.`);
      }
      processedPurposes.add(purpose);
    }
  }
}
