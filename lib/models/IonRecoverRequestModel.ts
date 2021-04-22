import IonDocumentModel from './IonDocumentModel';
import OperationType from '../enums/OperationType';

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
