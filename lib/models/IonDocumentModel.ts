import IonPublicKeyModel from './IonPublicKeyModel.js';
import IonServiceModel from './IonServiceModel.js';

/**
 * Defines the document structure used by ION.
 */
export default interface IonDocumentModel {
  publicKeys?: IonPublicKeyModel[];
  services?: IonServiceModel[];
}
