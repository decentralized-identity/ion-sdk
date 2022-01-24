import Encoder from './Encoder';
import ErrorCode from './ErrorCode';
import IonError from './IonError';
import IonKey from './IonKey';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';
import JwkEd25519 from './models/JwkEd25519';
import JwkEs256k from './models/JwkEs256k';
import OperationKeyType from './enums/OperationKeyType';
import SidetreeKeyJwk from './models/SidetreeKeyJwk';

/**
 * Class containing input validation methods.
 */
export default class InputValidator {
  /**
   * Validates the schema of a Ed25519 or secp256k1 JWK
   */
  public static validateOperationKey (operationKeyJwk: SidetreeKeyJwk, operationKeyType: OperationKeyType) {
    if (IonKey.isJwkEs256k(operationKeyJwk)) {
      InputValidator.validateEs256kOperationKey(operationKeyJwk, operationKeyType);
    } else if (IonKey.isJwkEd25519(operationKeyJwk)) {
      InputValidator.validateEd25519OperationKey(operationKeyJwk, operationKeyType);
    } else {
      throw new IonError(ErrorCode.UnsupportedKeyType, `JWK key should be secp256k1 or Ed25519.`);
    }
  }

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
   * Validates the schema of a Ed25519 JWK key.
   */
  public static validateEd25519OperationKey (operationKeyJwk: JwkEd25519, operationKeyType: OperationKeyType) {
    const allowedProperties = new Set(['kty', 'crv', 'x']);
    if (operationKeyType === OperationKeyType.Private) {
      allowedProperties.add('d');
    }
    for (const property in operationKeyJwk) {
      if (!allowedProperties.has(property)) {
        throw new IonError(ErrorCode.PublicKeyJwkEd25519HasUnexpectedProperty, `Ed25519 JWK key has unexpected property '${property}'.`);
      }
    }

    if (operationKeyJwk.crv !== 'Ed25519') {
      throw new IonError(ErrorCode.JwkEd25519MissingOrInvalidCrv, `Ed25519 JWK 'crv' property must be 'Ed25519' but got '${operationKeyJwk.crv}.'`);
    }

    if (operationKeyJwk.kty !== 'OKP') {
      throw new IonError(ErrorCode.JwkEd25519MissingOrInvalidKty, `Ed25519 JWK 'kty' property must be 'OKP' but got '${operationKeyJwk.kty}.'`);
    }

    // `x` needs 43 Base64URL encoded bytes to contain 256 bits.
    if (operationKeyJwk.x.length !== 43) {
      throw new IonError(ErrorCode.JwkEd25519HasIncorrectLengthOfX, `Ed25519 JWK 'x' property must be 43 bytes.`);
    }

    if (operationKeyType === OperationKeyType.Private && (operationKeyJwk.d === undefined || operationKeyJwk.d.length !== 43)) {
      throw new IonError(ErrorCode.JwkEd25519HasIncorrectLengthOfD, `Ed25519 JWK 'd' property must be 43 bytes.`);
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
