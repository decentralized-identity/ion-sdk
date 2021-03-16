import InputValidator from './InputValidator';
import IonPublicKeyModel from './models/IonPublicKeyModel';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose';
import JwkEs256k from './models/JwkEs256k';
const randomBytes = require('randombytes');
const secp256k1 = require('@transmute/did-key-secp256k1');

/**
 * Class containing operations related to keys used in ION.
 */
export default class IonKey {
  /**
   * Generates SECP256K1 key pair to be used in an operation.
   * Mainly used for testing.
   * @returns [publicKey, privateKey]
   */
  public static async generateEs256kDidDocumentKeyPair (input: { id: string, purposes?: IonPublicKeyPurpose[] }): Promise<[IonPublicKeyModel, JwkEs256k]> {
    const id = input.id;
    const purposes = input.purposes;

    InputValidator.validateId(id);
    InputValidator.validatePublicKeyPurposes(purposes);

    const [publicKey, privateKey] = await IonKey.generateEs256kKeyPair();
    const publicKeyModel: IonPublicKeyModel = {
      id,
      type: 'EcdsaSecp256k1VerificationKey2019',
      publicKeyJwk: publicKey
    };

    // Only add the `purposes` property If given `purposes` array has at least an entry.
    if (purposes !== undefined && purposes.length > 0) {
      publicKeyModel.purposes = purposes;
    }

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
    const keyPair = await secp256k1.Secp256k1KeyPair.generate({
      secureRandom: () => randomBytes(32),
    });
    const { publicKeyJwk, privateKeyJwk } = await keyPair.toJsonWebKeyPair(true);
    
    return [publicKeyJwk, privateKeyJwk];
  }
}
