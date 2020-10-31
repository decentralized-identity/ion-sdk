import IonPublicKeyPurpose from '../enums/IonPublicKeyPurpose';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonPublicKeyModel {
  id: string;
  type: string;
  publicKeyJwk: object;
  purposes?: IonPublicKeyPurpose[];
};
