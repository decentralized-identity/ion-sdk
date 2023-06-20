import IonAddPublicKeysActionModel from './IonAddPublicKeysActionModel.js';
import IonAddServicesActionModel from './IonAddServicesActionModel.js';
import IonRemovePublicKeysActionModel from './IonRemovePublicKeysActionModel.js';
import IonRemoveServicesActionModel from './IonRemoveServicesActionModel.js';
import OperationType from '../enums/OperationType.js';

/**
 * Data model representing a public key in the DID Document.
 */
export default interface IonUpdateRequestModel {
  type: OperationType;
  didSuffix: string;
  revealValue: string;
  delta: {
    updateCommitment: string,
    patches: (IonAddServicesActionModel | IonAddPublicKeysActionModel | IonRemoveServicesActionModel | IonRemovePublicKeysActionModel)[]
  },
  signedData: string
}
