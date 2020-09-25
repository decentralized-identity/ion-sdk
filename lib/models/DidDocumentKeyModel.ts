import DidDocumentKeyPurpose from './DidDocumentKeyPurpose';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface DidDocumentKeyModel {
  id: string;
  type: string;
  jwk: object;
  purpose: DidDocumentKeyPurpose[];
}
