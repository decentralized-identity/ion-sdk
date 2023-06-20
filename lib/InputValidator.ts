import Encoder from './Encoder.js';
import ErrorCode from './ErrorCode.js';
import IonError from './IonError.js';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose.js';
import JwkEs256k from './models/JwkEs256k.js';
import OperationKeyType from './enums/OperationKeyType.js';

/**
 * Class containing input validation methods.
 */
export default class InputValidator {
  /**
   * Validates the schema of a ES256K JWK key.
   */
  public static validateEs256kOperationKey (operationKeyJwk: JwkEs256k, operationKeyType: OperationKeyType) {
    const allowedProperties = new Set(['kty', 'crv', 'x', 'y']);
    if (operationKeyType === OperationKeyType.Private) {
      allowedProperties.add('d');
    }
    for (const property in operationKeyJwk) {
      if (!allowedProperties.has(property)) {
        throw new IonError(ErrorCode.PublicKeyJwkEs256kHasUnexpectedProperty, `SECP256K1 JWK key has unexpected property '${property}'.`);
      }
    }

    if (operationKeyJwk.crv !== 'secp256k1') {
      throw new IonError(ErrorCode.JwkEs256kMissingOrInvalidCrv, `SECP256K1 JWK 'crv' property must be 'secp256k1' but got '${operationKeyJwk.crv}.'`);
    }

    if (operationKeyJwk.kty !== 'EC') {
      throw new IonError(ErrorCode.JwkEs256kMissingOrInvalidKty, `SECP256K1 JWK 'kty' property must be 'EC' but got '${operationKeyJwk.kty}.'`);
    }

    // `x` and `y` need 43 Base64URL encoded bytes to contain 256 bits.
    if (operationKeyJwk.x.length !== 43) {
      throw new IonError(ErrorCode.JwkEs256kHasIncorrectLengthOfX, `SECP256K1 JWK 'x' property must be 43 bytes.`);
    }

    if (operationKeyJwk.y.length !== 43) {
      throw new IonError(ErrorCode.JwkEs256kHasIncorrectLengthOfY, `SECP256K1 JWK 'y' property must be 43 bytes.`);
    }

    if (operationKeyType === OperationKeyType.Private && (operationKeyJwk.d === undefined || operationKeyJwk.d.length !== 43)) {
      throw new IonError(ErrorCode.JwkEs256kHasIncorrectLengthOfD, `SECP256K1 JWK 'd' property must be 43 bytes.`);
    }
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
