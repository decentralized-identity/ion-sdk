import IonPublicKeyModel from './IonPublicKeyModel';
import IonServiceModel from './IonServiceModel';

/**
 * Defines the document structure used by ION.
 */
export default interface IonDocumentModel {
  publicKeys?: IonPublicKeyModel[];
  services?: IonServiceModel[];
}
