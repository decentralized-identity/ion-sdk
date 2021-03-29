import JwkEs256k from './models/JwkEs256k';
const secp256k1 = require('@transmute/did-key-secp256k1');

/**
 * Class containing operations related to keys used in ION.
 */
export default class IonSignature {
  public static async generateEs256kJws (signingObject: { payload: any, header?: Object, privateKeyJwk: JwkEs256k }): Promise<String> {
    const header = Object.assign(signingObject.header || {}, {
      alg: 'ES256K'
    });
    return secp256k1.ES256K.sign(
      signingObject.payload,
      signingObject.privateKeyJwk,
      header
    );
  }

  public static async verifyEs256kJws (jws: String | Buffer, publicKeyJwk: JwkEs256k): Promise<Boolean> {
    return secp256k1.ES256K.verify(
      jws,
      publicKeyJwk
    );
  }

  public static async generateEs256kDetachedJws (signingObject: { payload: Buffer, header?: Object, privateKeyJwk: JwkEs256k }): Promise<String> {
    const header = Object.assign(signingObject.header || {}, {
      alg: 'ES256K'
    });
    return secp256k1.ES256K.signDetached(
      signingObject.payload,
      signingObject.privateKeyJwk,
      header
    );
  }

  public static async verifyEs256kDetachedJws (jws: String | Buffer, publicKeyJwk: JwkEs256k, payload: Buffer): Promise<Boolean> {
    return secp256k1.ES256K.verifyDetached(
      jws,
      payload,
      publicKeyJwk
    );
  }
}
