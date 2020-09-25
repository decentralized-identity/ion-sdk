import { JWK } from 'jose';
import DidDocumentKeyModel from './models/DidDocumentKeyModel';
import DidDocumentKeyPurpose from './models/DidDocumentKeyPurpose';
import DidDocumentKeyValidator from './DidDocumentKeyValidator';
import JwkEs256k from './models/JwkEs256k';

/**
 * Class containing operations related to keys used in ION.
 */
export default class IonKey {
  /**
   * Generates SECP256K1 key pair to be used in an operation.
   * Mainly used for testing.
   * @returns [publicKey, privateKey]
   */
  public static async generateEs256kDidDocumentKeyPair (input: { id: string, purposes: DidDocumentKeyPurpose[] }): Promise<[DidDocumentKeyModel, JwkEs256k]> {
    const id = input.id;
    const purposes = input.purposes;

    DidDocumentKeyValidator.validateId(id);
    DidDocumentKeyValidator.validatePurposes(purposes);

    const [publicKey, privateKey] = await IonKey.generateEs256kKeyPair();
    const idDocumentKeyModel = {
      id,
      type: 'EcdsaSecp256k1VerificationKey2019',
      jwk: publicKey,
      purpose: purposes
    };

    return [idDocumentKeyModel, privateKey];
  }

  /**
   * Generates SECP256K1 key pair for ION operation use.
   * @returns [publicKey, privateKey]
   */
  public static async generateEs256kOperationKeyPair (): Promise<[JwkEs256k, JwkEs256k]> {
    const keyPair = await IonKey.generateEs256kKeyPair();
    return keyPair;
  }

  private static async generateEs256kKeyPair (): Promise<[JwkEs256k, JwkEs256k]> {
    const keyPair = await JWK.generate('EC', 'secp256k1');
    const publicKeyInternal = keyPair.toJWK();

    // Remove the auto-populated `kid` field.
    const publicKey = {
      kty: publicKeyInternal.kty,
      crv: publicKeyInternal.crv,
      x: publicKeyInternal.x,
      y: publicKeyInternal.y
    };

    const privateKey = Object.assign({ d: keyPair.d }, publicKey);
    return [publicKey, privateKey];
  }
}
