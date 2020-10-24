import DidDocumentKeyPurpose from '../enums/DidDocumentKeyPurpose';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface DidDocumentKeyModel {
  id: string;
  type: string;
  publicKeyJwk: object;
  purposes: DidDocumentKeyPurpose[];
};
