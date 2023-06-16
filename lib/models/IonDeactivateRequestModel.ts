import OperationType from '../enums/OperationType.js';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonDeactivateRequestModel {
  type: OperationType;
  didSuffix: string;
  revealValue: string;
  signedData: string;
};
