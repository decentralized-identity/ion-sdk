import IonPublicKeyModel from './IonPublicKeyModel';

export default interface IonAddPublicKeysActionModel {
    action: string;
    publicKeys: IonPublicKeyModel[];
}
