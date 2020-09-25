import DidDocumentKeyPurpose from './models/DidDocumentKeyPurpose';
import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';

/**
 * Class containing operations related to keys specified within a DID Document.
 */
export default class DidDocumentKeyValidator {
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
  public static validatePurposes (purposes: DidDocumentKeyPurpose[]) {
    if (purposes.length === 0) {
      throw new IonError(ErrorCode.IonKeyPurposeNotDefined, `ION key 'purpose' is not defined.`);
    }

    // Validate that all purposes are be unique.
    const processedPurposes: Set<DidDocumentKeyPurpose> = new Set();
    for (const purpose of purposes) {
      if (processedPurposes.has(purpose)) {
        throw new IonError(ErrorCode.IonKeyPurposeDuplicated, `ION key purpose '${purpose}' already specified.`);
      }
      processedPurposes.add(purpose);
    }
  }
}
