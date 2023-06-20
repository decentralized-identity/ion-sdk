import IonDocumentModel from './IonDocumentModel.js';
import OperationType from '../enums/OperationType.js';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonRecoverRequestModel {
  type: OperationType;
  didSuffix: string;
  revealValue: string;
  delta: {
    updateCommitment: string,
    patches: {
        action: string,
        document: IonDocumentModel;
    }[]
  },
  signedData: string
}
