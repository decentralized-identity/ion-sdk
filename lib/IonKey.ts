import * as Ed25519 from '@noble/ed25519';
import * as Secp256k1 from '@noble/secp256k1';
import InputValidator from './InputValidator.js';
import IonPublicKeyModel from './models/IonPublicKeyModel.js';
import IonPublicKeyPurpose from './enums/IonPublicKeyPurpose.js';
import JwkEd25519 from './models/JwkEd25519.js';
import JwkEs256k from './models/JwkEs256k.js';
import { base64url } from 'multiformats/bases/base64';

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
    const privateKeyBytes = Secp256k1.utils.randomPrivateKey();
    const compressedPublicKeyBytes = Secp256k1.getPublicKey(privateKeyBytes);
    const compressedPublicKeyHex = Secp256k1.etc.bytesToHex(compressedPublicKeyBytes);
    const curvePoints = Secp256k1.ProjectivePoint.fromHex(compressedPublicKeyHex);
    const uncompressedPublicKeyBytes = curvePoints.toRawBytes(false); // false = uncompressed

    // we need uncompressed public key so that it contains both the x and y values for the JWK format:
    // the first byte is a header that indicates whether the key is uncompressed (0x04 if uncompressed).
    // bytes 1 - 32 represent X
    // bytes 33 - 64 represent Y

    const d = base64url.baseEncode(privateKeyBytes);
    // skip the first byte because it's used as a header to indicate whether the key is uncompressed
    const x = base64url.baseEncode(uncompressedPublicKeyBytes.subarray(1, 33));
    const y = base64url.baseEncode(uncompressedPublicKeyBytes.subarray(33, 65));

    const publicJwk = {
      // alg: 'ES256K',
      kty: 'EC',
      crv: 'secp256k1',
      x,
      y
    };
    const privateJwk = { ...publicJwk, d };

    return [publicJwk, privateJwk];
  }

  /**
   * Generates Ed25519 key pair to be used in an operation.
   * Mainly used for testing.
   * @returns [publicKey, privateKey]
   */
  public static async generateEd25519DidDocumentKeyPair (input: { id: string, purposes?: IonPublicKeyPurpose[] }): Promise<[IonPublicKeyModel, JwkEd25519]> {
    const id = input.id;
    const purposes = input.purposes;

    InputValidator.validateId(id);
    InputValidator.validatePublicKeyPurposes(purposes);

    const [publicKey, privateKey] = await IonKey.generateEd25519KeyPair();
    const publicKeyModel: IonPublicKeyModel = {
      id,
      type: 'JsonWebKey2020',
      publicKeyJwk: publicKey
    };

    // Only add the `purposes` property If given `purposes` array has at least an entry.
    if (purposes !== undefined && purposes.length > 0) {
      publicKeyModel.purposes = purposes;
    }

    return [publicKeyModel, privateKey];
  }

  /**
   * Generates Ed25519 key pair for ION operation use.
   * @returns [publicKey, privateKey]
   */
  public static async generateEd25519OperationKeyPair (): Promise<[JwkEd25519, JwkEd25519]> {
    const keyPair = await IonKey.generateEd25519KeyPair();
    return keyPair;
  }

  private static async generateEd25519KeyPair (): Promise<[JwkEd25519, JwkEd25519]> {
    const privateKeyBytes = Ed25519.utils.randomPrivateKey();
    const privateKeyHex = Ed25519.etc.bytesToHex(privateKeyBytes);
    const publicKeyBytes = await Ed25519.getPublicKeyAsync(privateKeyHex);

    const d = base64url.baseEncode(privateKeyBytes);
    const x = base64url.baseEncode(publicKeyBytes);

    const publicJwk = {
      // alg: 'EdDSA',
      kty: 'OKP',
      crv: 'Ed25519',
      x
    };
    const privateJwk = { ...publicJwk, d };

    return [publicJwk, privateJwk];
  }

  public static isJwkEs256k (key: JwkEs256k | JwkEd25519): key is JwkEs256k {
    return key.crv === 'secp256k1' && key.kty === 'EC';
  };

  public static isJwkEd25519 (key: JwkEs256k | JwkEd25519): key is JwkEd25519 {
    return key.crv === 'Ed25519' && key.kty === 'OKP';
  };
}
