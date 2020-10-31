import IonDocumentModel from './IonDocumentModel';
import OperationType from '../enums/OperationType';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonCreateRequestModel {
  type: OperationType;
  suffixData: {
    deltaHash: string;
    recoveryCommitment: string;
  };
  delta: {
    updateCommitment: string;
    patches: {
      action: string;
      document: IonDocumentModel;
    }[];
  }
}
