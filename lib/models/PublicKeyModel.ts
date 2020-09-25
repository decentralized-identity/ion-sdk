import PublicKeyPurpose from './PublicKeyPurpose';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface PublicKeyModel {
  id: string;
  type: string;
  jwk: object;
  purpose: PublicKeyPurpose[];
}
