import { JWK } from 'jose';
import IonKeyInternal from './IonKeyInternal';
import JwkEs256k from './models/JwkEs256k';
import PublicKeyModel from './models/PublicKeyModel';
import PublicKeyPurpose from './models/PublicKeyPurpose';

/**
 * Class containing operations related to keys used in ION.
 */
export default class IonKey {
  /**
   * Generates SECP256K1 key pair to be used in an operation.
   * Mainly used for testing.
   * @returns [publicKey, privateKey]
   */
  public static async generateEs256kDidDocumentKeyPair (id: string, purposes: PublicKeyPurpose[]): Promise<[PublicKeyModel, JwkEs256k]> {
    IonKeyInternal.validateId(id);
    IonKeyInternal.validatePurposes(purposes);

    const [publicKey, privateKey] = await IonKey.generateEs256kKeyPair();
    const publicKeyModel = {
      id,
      type: 'EcdsaSecp256k1VerificationKey2019',
      jwk: publicKey,
      purpose: purposes || Object.values(PublicKeyPurpose)
    };

    return [publicKeyModel, privateKey];
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
