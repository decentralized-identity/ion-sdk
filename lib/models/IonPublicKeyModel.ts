import IonPublicKeyPurpose from '../enums/IonPublicKeyPurpose';
import JwkEd25519 from '../models/JwkEd25519';
import JwkEs256k from '../models/JwkEs256k';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonPublicKeyModel {
  id: string;
  type: string;
  publicKeyJwk: JwkEs256k | JwkEd25519;
  purposes?: IonPublicKeyPurpose[];
};
