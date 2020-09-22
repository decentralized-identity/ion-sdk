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
  public static validatePurposes (purposes: PublicKeyPurpose[]) {
    if (purposes.length === 0) {
      throw new IonError(ErrorCode.IonKeyPurposeNotDefined, `No key purpose is defined.`);
    }
  }
}
