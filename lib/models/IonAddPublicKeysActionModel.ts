import IonPublicKeyModel from './IonPublicKeyModel.js';

export default interface IonAddPublicKeysActionModel {
    action: string;
    publicKeys: IonPublicKeyModel[];
}
