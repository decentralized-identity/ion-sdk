import IonAddPublicKeysActionModel from './IonAddPublicKeysActionModel';
import IonAddServicesActionModel from './IonAddServicesActionModel';
import IonRemovePublicKeysActionModel from './IonRemovePublicKeysActionModel';
import IonRemoveServicesActionModel from './IonRemoveServicesActionModel';
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
    patches: (IonAddServicesActionModel | IonAddPublicKeysActionModel | IonRemoveServicesActionModel | IonRemovePublicKeysActionModel)[]
  },
  signedData: string
}
