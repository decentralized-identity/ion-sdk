import { Ed25519KeyPair } from '@transmute/ed25519-key-pair';
import ErrorCode from './ErrorCode';
import ISigner from './interfaces/ISigner';
import InputValidator from './InputValidator';
import IonError from './IonError';
import IonKey from './IonKey';
import { JWS } from '@transmute/jose-ld';
import OperationKeyType from './enums/OperationKeyType';
import { Secp256k1KeyPair } from '@transmute/secp256k1-key-pair';
import SidetreeKeyJwk from './models/SidetreeKeyJwk';

/**
 * An ISigner implementation that uses a given local private key.
 */
export default class LocalSigner implements ISigner {
  /**
   * Creates a new local signer using the given private key.
   */
  public static create (privateKey: SidetreeKeyJwk): ISigner {
    return new LocalSigner(privateKey);
  }

  private constructor (private privateKey: SidetreeKeyJwk) {
    InputValidator.validateOperationKey(privateKey, OperationKeyType.Private);
  }

  public async sign (header: object, content: object): Promise<string> {
    const publicKeyJwk = {
      ...this.privateKey,
      d: undefined
    };
    if (IonKey.isJwkEs256k(publicKeyJwk)) {
      const key = await Secp256k1KeyPair.from({
        type: 'JsonWebKey2020',
        publicKeyJwk,
        privateKeyJwk: this.privateKey
      } as any);
      const signer = key.signer();
      const jwsSigner = await JWS.createSigner(signer, 'ES256K', {
        detached: false,
        header
      });
      const compactJws = await jwsSigner.sign({ data: content });
      return compactJws;
    } else if (IonKey.isJwkEd25519(publicKeyJwk)) {
      const key = await Ed25519KeyPair.from({
        type: 'JsonWebKey2020',
        publicKeyJwk,
        privateKeyJwk: this.privateKey
      } as any);
      const signer = key.signer();
      const jwsSigner = await JWS.createSigner(signer, 'EdDSA', {
        detached: false,
        header
      });
      const compactJws = await jwsSigner.sign({ data: content });
      return compactJws;
    } else {
      throw new IonError(ErrorCode.UnsupportedKeyType, `JWK key should be secp256k1 or Ed25119.`);
    }
  }
}
