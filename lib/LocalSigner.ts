import { Ed25519KeyPair } from '@transmute/ed25519-key-pair';
import ErrorCode from './ErrorCode';
import ISigner from './interfaces/ISigner';
import InputValidator from './InputValidator';
import IonError from './IonError';
import IonKey from './IonKey';
import { JWS } from '@transmute/jose-ld';
import JwkEd25519 from './models/JwkEd25519';
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
  public static create (privateKey: JwkEs256k | JwkEd25519): ISigner {
    return new LocalSigner(privateKey);
  }

  private constructor (private privateKey: JwkEs256k | JwkEd25519) {
    if (IonKey.isJwkEs256k(privateKey)) {
      InputValidator.validateEs256kOperationKey(privateKey, OperationKeyType.Private);
    } else if (IonKey.isJwkEd25519(privateKey)) {
      InputValidator.validateEd25519OperationKey(privateKey, OperationKeyType.Private);
    } else {
      throw new IonError(ErrorCode.UnsupportedKeyType, `JWK key should be Es256k or Ed25119.`);
    }
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
      throw new IonError(ErrorCode.UnsupportedKeyType, `JWK key should be Es256k or Ed25119.`);
    }
  }
}
