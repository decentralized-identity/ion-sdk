import DidDocumentModel from './DidDocumentModel';
import OperationType from '../enums/OperationType';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface DidCreateRequestModel {
  type: OperationType;
  suffixData: {
    deltaHash: string;
    recoveryCommitment: string;
  };
  delta: {
    updateCommitment: string;
    patches: {
      action: string;
      document: DidDocumentModel;
    }[];
  }
}
