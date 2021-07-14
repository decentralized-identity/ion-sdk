import ISigner from './interfaces/ISigner';
import InputValidator from './InputValidator';
import JwkEs256k from './models/JwkEs256k';
import OperationKeyType from './enums/OperationKeyType';
const secp256k1 = require('@transmute/did-key-secp256k1');

/**
 * An ISigner implementation that uses a given local private key.
 */
export default class LocalSigner implements ISigner {
  /**
   * Creates a new local signer using the given private key.
   */
  public static create (privateKey: JwkEs256k): ISigner {
    return new LocalSigner(privateKey);
  }

  private constructor (private privateKey: JwkEs256k) {
    InputValidator.validateEs256kOperationKey(privateKey, OperationKeyType.Private);
  }

  public async sign (header: object, content: object): Promise<string> {
    const compactJws = await secp256k1.ES256K.sign(content, this.privateKey, header);
    return compactJws;
  }
}
