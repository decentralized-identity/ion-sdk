import DidPublicKeyModel from './DidPublicKeyModel';
import DidServiceModel from './DidServiceModel';

/**
 * Defines the document structure used by ION.
 */
export default interface DidDocumentModel {
  publicKeys?: DidPublicKeyModel[];
  services?: DidServiceModel[];
}
