import IonPublicKeyModel from './IonPublicKeyModel';
import IonServiceModel from './IonServiceModel';
import OperationType from '../enums/OperationType';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonUpdateRequestModel {
  type: OperationType;
  didSuffix: string;
  revealValue: string;
  delta: {
    updateCommitment: string,
    patches: {
        action: string,
        servicesToAdd?: IonServiceModel[],
        publicKeys?: IonPublicKeyModel[],
        ids?: string[]
    }[]
  },
  signedData: string
}
