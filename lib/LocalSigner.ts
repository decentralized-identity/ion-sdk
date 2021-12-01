import ISigner from './interfaces/ISigner';
import InputValidator from './InputValidator';
import { JWS } from '@transmute/jose-ld';
import JwkEs256k from './models/JwkEs256k';
import OperationKeyType from './enums/OperationKeyType';
import { Secp256k1KeyPair } from '@transmute/secp256k1-key-pair';

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
    const key = await Secp256k1KeyPair.from({
      type: 'JsonWebKey2020',
      publicKeyJwk: this.privateKey,
      privateKeyJwk: this.privateKey
    } as any);
    const signer = key.signer();
    const jwsSigner = await JWS.createSigner(signer, 'ES256K', {
      detached: false,
      header
    });
    const compactJws = await jwsSigner.sign({ data: content });
    return compactJws;
  }
}
